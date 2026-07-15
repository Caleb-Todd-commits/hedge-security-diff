import ts from "typescript";
import type { SurfaceEdge, SurfaceNode } from "../domain/schemas.js";
import type { SourceFile } from "./files.js";

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ALL"]);
const MAX_HELPER_DEPTH = 5;

export interface AstOperation {
  position?: number;
  kind: SurfaceNode["kind"];
  edgeKind: SurfaceEdge["kind"];
  label: string;
  trustZone: SurfaceNode["trustZone"];
  line: number;
  metadata: Record<string, unknown>;
}

export interface AstSecretUse {
  name: string;
  line: number;
}

export interface AstControl {
  sourcePath?: string;
  type:
    | "authentication"
    | "authorization"
    | "validation"
    | "rate-limit"
    | "size-limit"
    | "content-type"
    | "encryption"
    | "logging"
    | "ownership"
    | "other";
  label: string;
  line: number;
  confidence: number;
}

export interface AstEntrypoint {
  framework: "nextjs" | "express";
  method: string;
  path: string;
  line: number;
  controls: AstControl[];
  operations: AstOperation[];
  secrets: AstSecretUse[];
  handlerName?: string;
}

export interface AstMiddlewareRule {
  framework: "nextjs";
  matchers: string[];
  controls: AstControl[];
  line: number;
  sourcePath: string;
}

export interface AstFileFacts {
  entrypoints: AstEntrypoint[];
  middlewareRules: AstMiddlewareRule[];
  allSecrets: AstSecretUse[];
  parseDiagnostics: string[];
}

interface HandlerResolution {
  node?: ts.FunctionLikeDeclaration;
  wrapperControls: AstControl[];
  displayName?: string;
}

interface HandlerAnalysis {
  controls: AstControl[];
  operations: AstOperation[];
  secrets: AstSecretUse[];
}

interface ExpressMiddleware {
  receiver: string;
  pathPrefix?: string;
  controls: AstControl[];
  position: number;
}

interface ExpressRouteCall {
  receiver: string;
  path: string;
  routeArguments: ts.Expression[];
}

export function extractTypeScriptFacts(file: SourceFile, framework: string): AstFileFacts {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    scriptKindFor(file.path)
  );
  const parseDiagnostics = (
    (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ??
    []
  ).map((diagnostic: ts.Diagnostic) =>
    ts.flattenDiagnosticMessageText(diagnostic.messageText, " ")
  );
  const functions = collectNamedFunctions(source);
  const expressReceivers = collectExpressReceivers(source);
  const entrypoints: AstEntrypoint[] = [];

  if (framework === "nextjs" && /(^|\/)app\/.+\/route\.[jt]sx?$/.test(file.path)) {
    for (const statement of source.statements) {
      const next = nextRouteHandler(statement, functions, source);
      if (!next?.node) continue;
      const analysis = analyzeHandler(next.node, source, functions);
      entrypoints.push({
        framework: "nextjs",
        method: next.method,
        path: nextRoutePath(file.path),
        line: lineOf(source, next.node),
        controls: dedupeControls([...next.wrapperControls, ...analysis.controls]),
        operations: analysis.operations,
        secrets: analysis.secrets,
        handlerName: next.name
      });
    }
  }

  if (framework === "nextjs") {
    const moduleServerAction = hasUseServerDirective(source.statements);
    for (const statement of source.statements) {
      const action = nextServerActionHandler(statement, functions, source, moduleServerAction);
      if (!action?.node) continue;
      const actionInputs = new Set(
        action.node.parameters.flatMap((parameter) => bindingNames(parameter.name))
      );
      const analysis = analyzeHandler(action.node, source, functions, new Set(), 0, actionInputs);
      entrypoints.push({
        framework: "nextjs",
        method: "ACTION",
        path: `/server-action/${action.name}`,
        line: lineOf(source, action.node),
        controls: dedupeControls([...action.wrapperControls, ...analysis.controls]),
        operations: analysis.operations,
        secrets: analysis.secrets,
        handlerName: action.name
      });
    }
  }

  if (framework === "express" || containsExpressCalls(source, expressReceivers)) {
    const middleware = collectExpressMiddleware(source, functions, expressReceivers);
    visit(source, (node) => {
      if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
      const method = node.expression.name.text.toUpperCase();
      if (!HTTP_METHODS.has(method)) return;
      const route = resolveExpressRouteCall(node, source, expressReceivers);
      if (!route) return;
      const analyses: HandlerAnalysis[] = [];
      const wrapperControls: AstControl[] = [];
      let handlerName: string | undefined;
      for (const argument of route.routeArguments) {
        const resolution = resolveHandler(argument, functions, source);
        wrapperControls.push(...resolution.wrapperControls);
        if (ts.isIdentifier(argument)) {
          const inferred = wrapperControl(argument.text, lineOf(source, argument));
          if (inferred) wrapperControls.push(inferred);
        }
        if (!resolution.node) continue;
        analyses.push(analyzeHandler(resolution.node, source, functions));
        handlerName = resolution.displayName ?? handlerName;
      }
      const combined = combineAnalyses(analyses);
      const applicableMiddleware = middleware
        .filter(
          (item) =>
            item.receiver === route.receiver &&
            item.position < node.getStart(source) &&
            middlewareMatchesPath(item.pathPrefix, route.path)
        )
        .flatMap((item) => item.controls);
      entrypoints.push({
        framework: "express",
        method,
        path: route.path,
        line: lineOf(source, node),
        controls: dedupeControls([
          ...applicableMiddleware,
          ...wrapperControls,
          ...combined.controls
        ]),
        operations: combined.operations,
        secrets: combined.secrets,
        handlerName: handlerName ?? route.routeArguments.at(-1)?.getText(source)
      });
    });
  }

  const middlewareRules =
    framework === "nextjs" && /(^|\/)middleware\.[cm]?[jt]sx?$/.test(file.path)
      ? extractNextMiddlewareRules(file.path, source, functions)
      : [];

  return {
    entrypoints: dedupeEntrypoints(entrypoints),
    middlewareRules,
    allSecrets: extractSecrets(source),
    parseDiagnostics
  };
}

function collectNamedFunctions(source: ts.SourceFile): Map<string, ts.FunctionLikeDeclaration> {
  const result = new Map<string, ts.FunctionLikeDeclaration>();
  visit(source, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name) {
      result.set(node.name.text, node);
      return;
    }
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    if (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) {
      result.set(node.name.text, node.initializer);
    }
  });
  return result;
}

function nextRouteHandler(
  statement: ts.Statement,
  functions: Map<string, ts.FunctionLikeDeclaration>,
  source: ts.SourceFile
): {
  method: string;
  node?: ts.FunctionLikeDeclaration;
  name?: string;
  wrapperControls: AstControl[];
} | null {
  if (ts.isFunctionDeclaration(statement) && statement.name && hasExportModifier(statement)) {
    const method = statement.name.text.toUpperCase();
    if (HTTP_METHODS.has(method)) {
      return { method, node: statement, name: statement.name.text, wrapperControls: [] };
    }
  }

  if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const method = declaration.name.text.toUpperCase();
      if (!HTTP_METHODS.has(method)) continue;
      const resolution = resolveHandler(declaration.initializer, functions, source);
      return {
        method,
        node: resolution.node,
        name: resolution.displayName ?? declaration.name.text,
        wrapperControls: resolution.wrapperControls
      };
    }
  }

  if (
    ts.isExportDeclaration(statement) &&
    statement.exportClause &&
    ts.isNamedExports(statement.exportClause)
  ) {
    for (const element of statement.exportClause.elements) {
      const exported = element.name.text.toUpperCase();
      if (!HTTP_METHODS.has(exported)) continue;
      const localName = element.propertyName?.text ?? element.name.text;
      const node = functions.get(localName);
      return { method: exported, node, name: localName, wrapperControls: [] };
    }
  }

  return null;
}

function nextServerActionHandler(
  statement: ts.Statement,
  functions: Map<string, ts.FunctionLikeDeclaration>,
  source: ts.SourceFile,
  moduleServerAction: boolean
): { node?: ts.FunctionLikeDeclaration; name: string; wrapperControls: AstControl[] } | null {
  if (ts.isFunctionDeclaration(statement) && statement.name && hasExportModifier(statement)) {
    if (!isAsyncFunction(statement)) return null;
    if (!moduleServerAction && !hasUseServerDirective(statement.body?.statements ?? []))
      return null;
    return { node: statement, name: statement.name.text, wrapperControls: [] };
  }

  if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const resolution = resolveHandler(declaration.initializer, functions, source);
      if (!resolution.node || !isAsyncFunction(resolution.node)) continue;
      if (
        !moduleServerAction &&
        !hasUseServerDirective(
          resolution.node.body && ts.isBlock(resolution.node.body)
            ? resolution.node.body.statements
            : []
        )
      ) {
        continue;
      }
      return {
        node: resolution.node,
        name: declaration.name.text,
        wrapperControls: resolution.wrapperControls
      };
    }
  }
  return null;
}

function hasUseServerDirective(statements: readonly ts.Statement[]): boolean {
  return statements.some(
    (statement) =>
      ts.isExpressionStatement(statement) &&
      ts.isStringLiteralLike(statement.expression) &&
      statement.expression.text === "use server"
  );
}

function isAsyncFunction(node: ts.FunctionLikeDeclaration): boolean {
  return Boolean(ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Async);
}

function analyzeHandler(
  node: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
  functions: Map<string, ts.FunctionLikeDeclaration>,
  visited = new Set<ts.FunctionLikeDeclaration>(),
  depth = 0,
  seedTainted = new Set<string>(),
  seedSecrets = new Set<string>()
): HandlerAnalysis {
  if (visited.has(node) || depth > MAX_HELPER_DEPTH) return emptyAnalysis();
  visited.add(node);
  const controls: AstControl[] = [];
  const operations: AstOperation[] = [];
  const secrets: AstSecretUse[] = [];
  const body = node.body;
  if (!body) return { controls, operations, secrets };
  const tainted = collectTaintedIdentifiers(node, source, seedTainted);
  const secretIdentifiers = collectSecretIdentifiers(node, source, seedSecrets);

  visitScoped(body, (current) => {
    if (ts.isCallExpression(current)) {
      const callee = current.expression.getText(source);
      const simpleName = lastSegment(callee);
      const line = lineOf(source, current);

      const control = classifyControlCall(simpleName, callee, current, source, line);
      if (control) controls.push(control);

      const operation = classifyOperationCall(
        current,
        source,
        line,
        current.getStart(source),
        tainted,
        secretIdentifiers
      );
      if (operation) operations.push(operation);

      if (ts.isIdentifier(current.expression)) {
        const helper = functions.get(current.expression.text);
        if (helper && helper !== node) {
          const nested = analyzeHandler(
            helper,
            source,
            functions,
            new Set(visited),
            depth + 1,
            taintedParametersForCall(current, helper, source, tainted),
            secretParametersForCall(current, helper, source, secretIdentifiers)
          );
          controls.push(...nested.controls);
          operations.push(...nested.operations);
          secrets.push(...nested.secrets);
        }
      }
    }

    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
      const name = current.name.text;
      const initializer = current.initializer?.getText(source) ?? "";
      if (
        /^(ownerId|userId|tenantId|accountId)$/i.test(name) &&
        /session|user|tenant|account/i.test(initializer)
      ) {
        controls.push({
          type: "ownership",
          label: "Resource ownership derivation",
          line: lineOf(source, current),
          confidence: 0.84
        });
      }
    }

    if (ts.isBinaryExpression(current)) {
      const text = current.getText(source);
      const line = lineOf(source, current);
      if (/\b(role|permission|isAdmin|admin)\b/i.test(text)) {
        controls.push({
          type: "authorization",
          label: "Authorization or role comparison",
          line,
          confidence: 0.86
        });
      }
      if (/\b(ownerId|userId|tenantId|accountId)\b/i.test(text)) {
        controls.push({
          type: "ownership",
          label: "Resource ownership comparison",
          line,
          confidence: 0.86
        });
      }
      if (/\b(file\.size|content-length|maxFileSize|sizeLimit)\b/i.test(text)) {
        controls.push({
          type: "size-limit",
          label: "Payload or file size limit",
          line,
          confidence: 0.9
        });
      }
    }

    const secret = secretUse(current, source);
    if (secret) secrets.push(secret);
  });

  return {
    controls: dedupeControls(controls),
    operations: dedupeOperations(operations),
    secrets: dedupeSecrets(secrets)
  };
}

function extractNextMiddlewareRules(
  sourcePath: string,
  source: ts.SourceFile,
  functions: Map<string, ts.FunctionLikeDeclaration>
): AstMiddlewareRule[] {
  const matchers = extractNextMiddlewareMatchers(source);
  const controls: AstControl[] = [];
  let line = 1;

  for (const statement of source.statements) {
    let resolution: HandlerResolution | undefined;
    if (
      ts.isFunctionDeclaration(statement) &&
      statement.name?.text === "middleware" &&
      hasExportModifier(statement)
    ) {
      resolution = { node: statement, wrapperControls: [], displayName: "middleware" };
    } else if (ts.isExportAssignment(statement)) {
      resolution = resolveHandler(statement.expression, functions, source);
    } else if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "middleware") continue;
        resolution = resolveHandler(declaration.initializer, functions, source);
      }
    }
    if (!resolution) continue;
    line = lineOf(source, resolution.node ?? statement);
    controls.push(...resolution.wrapperControls);
    if (resolution.node)
      controls.push(...analyzeHandler(resolution.node, source, functions).controls);
  }

  const sourced = dedupeControls(controls).map((control) => ({ ...control, sourcePath }));
  if (!sourced.length) return [];
  return [{ framework: "nextjs", matchers, controls: sourced, line, sourcePath }];
}

function extractNextMiddlewareMatchers(source: ts.SourceFile): string[] {
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement) || !hasExportModifier(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "config") continue;
      if (!declaration.initializer || !ts.isObjectLiteralExpression(declaration.initializer))
        continue;
      for (const property of declaration.initializer.properties) {
        if (!ts.isPropertyAssignment(property)) continue;
        const name = property.name.getText(source).replace(/["'`]/g, "");
        if (name !== "matcher") continue;
        const direct = staticString(property.initializer);
        if (direct) return [direct];
        if (ts.isArrayLiteralExpression(property.initializer)) {
          return property.initializer.elements
            .map((element) => (ts.isExpression(element) ? staticString(element) : undefined))
            .filter((value): value is string => Boolean(value));
        }
      }
    }
  }
  return [];
}

export function nextMiddlewareMatchesPath(matchers: string[], routePath: string): boolean {
  if (!matchers.length) return true;
  return matchers.some((matcher) => {
    const regex = nextMatcherRegex(matcher);
    return regex ? regex.test(routePath) : false;
  });
}

function nextMatcherRegex(matcher: string): RegExp | null {
  if (!matcher || matcher === "/:path*") return /^\/.*$/;
  // Complex regular expressions and object matchers require the Next.js matcher
  // engine. Refusing to infer them is safer than asserting a route is protected.
  if (matcher.includes("(") || matcher.includes("[") || matcher.includes("{")) return null;
  const segments = matcher.split("/").filter(Boolean);
  let pattern = "^";
  for (const segment of segments) {
    if (segment.startsWith(":")) {
      if (segment.endsWith("*")) pattern += "(?:/.*)?";
      else if (segment.endsWith("?")) pattern += "(?:/[^/]+)?";
      else pattern += "/[^/]+";
      continue;
    }
    pattern += `/${escapeRegExp(segment)}`;
  }
  return new RegExp(`${pattern || "^/"}/?$`);
}

function collectExpressMiddleware(
  source: ts.SourceFile,
  functions: Map<string, ts.FunctionLikeDeclaration>,
  receivers: Set<string>
): ExpressMiddleware[] {
  const middleware: ExpressMiddleware[] = [];
  visit(source, (node) => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
    if (node.expression.name.text !== "use") return;
    const receiver = node.expression.expression.getText(source);
    if (!isExpressReceiver(receiver, receivers)) return;
    const first = node.arguments[0];
    const pathPrefix = staticString(first);
    const middlewareArguments = [...node.arguments].slice(pathPrefix ? 1 : 0);
    const found: AstControl[] = [];
    for (const argument of middlewareArguments) {
      const resolution = resolveHandler(argument, functions, source);
      found.push(...resolution.wrapperControls);
      if (resolution.node) {
        found.push(...analyzeHandler(resolution.node, source, functions).controls);
      }
      if (ts.isIdentifier(argument)) {
        const inferred = wrapperControl(argument.text, lineOf(source, argument));
        if (inferred) found.push(inferred);
      }
    }
    middleware.push({
      receiver,
      pathPrefix,
      controls: dedupeControls(found),
      position: node.getStart(source)
    });
  });
  return middleware;
}

function resolveExpressRouteCall(
  call: ts.CallExpression,
  source: ts.SourceFile,
  receivers: Set<string>
): ExpressRouteCall | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const directReceiver = call.expression.expression.getText(source);
  if (isExpressReceiver(directReceiver, receivers)) {
    const pathArg = call.arguments[0];
    return {
      receiver: directReceiver,
      path: staticString(pathArg) ?? "/unknown",
      routeArguments: [...call.arguments].slice(pathArg ? 1 : 0)
    };
  }

  const chain = call.expression.expression;
  if (
    ts.isCallExpression(chain) &&
    ts.isPropertyAccessExpression(chain.expression) &&
    chain.expression.name.text === "route"
  ) {
    const receiver = chain.expression.expression.getText(source);
    if (!isExpressReceiver(receiver, receivers)) return null;
    return {
      receiver,
      path: staticString(chain.arguments[0]) ?? "/unknown",
      routeArguments: [...call.arguments]
    };
  }
  return null;
}

function middlewareMatchesPath(prefix: string | undefined, routePath: string): boolean {
  if (!prefix || prefix === "/") return true;
  if (routePath === "/unknown") return false;
  const normalized = prefix.endsWith("/") && prefix !== "/" ? prefix.slice(0, -1) : prefix;
  return routePath === normalized || routePath.startsWith(`${normalized}/`);
}

function resolveHandler(
  node: ts.Expression | undefined,
  functions: Map<string, ts.FunctionLikeDeclaration>,
  source: ts.SourceFile
): HandlerResolution {
  if (!node) return { wrapperControls: [] };
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    return { node, wrapperControls: [], displayName: "inline" };
  }
  if (ts.isIdentifier(node)) {
    return { node: functions.get(node.text), wrapperControls: [], displayName: node.text };
  }
  if (ts.isCallExpression(node)) {
    const callee = node.expression.getText(source);
    const control = wrapperControl(lastSegment(callee), lineOf(source, node));
    const candidates = [...node.arguments].reverse();
    for (const candidate of candidates) {
      const nested = resolveHandler(candidate, functions, source);
      if (nested.node) {
        return {
          node: nested.node,
          displayName: `${callee}(${nested.displayName ?? "handler"})`,
          wrapperControls: dedupeControls([
            ...(control ? [control] : []),
            ...nested.wrapperControls
          ])
        };
      }
    }
    return { wrapperControls: control ? [control] : [], displayName: callee };
  }
  return { wrapperControls: [] };
}

function wrapperControl(name: string, line: number): AstControl | null {
  if (/^(auth|withAuth|requireAuth|authenticated|protect|protectedRoute)$/i.test(name)) {
    return {
      type: "authentication",
      label: `Authentication wrapper: ${name}`,
      line,
      confidence: 0.9
    };
  }
  if (/^(withRole|requireRole|withPermission|authorize|adminOnly)$/i.test(name)) {
    return {
      type: "authorization",
      label: `Authorization wrapper: ${name}`,
      line,
      confidence: 0.88
    };
  }
  if (/^(rateLimit|withRateLimit|throttle)$/i.test(name)) {
    return { type: "rate-limit", label: `Rate-limit wrapper: ${name}`, line, confidence: 0.86 };
  }
  if (/^(validate|withValidation|validateBody)$/i.test(name)) {
    return { type: "validation", label: `Validation wrapper: ${name}`, line, confidence: 0.84 };
  }
  return null;
}

function classifyControlCall(
  simpleName: string,
  callee: string,
  call: ts.CallExpression,
  source: ts.SourceFile,
  line: number
): AstControl | null {
  if (
    /^(auth|getServerSession|requireAuth|currentUser|validateSession|getToken|verifyToken)$/i.test(
      simpleName
    )
  ) {
    return {
      type: "authentication",
      label: `Authentication check: ${simpleName}`,
      line,
      confidence: 0.93
    };
  }
  if (/^(authorize|requireRole|hasPermission|assertPermission|isAdmin)$/i.test(simpleName)) {
    return {
      type: "authorization",
      label: `Authorization check: ${simpleName}`,
      line,
      confidence: 0.92
    };
  }
  if (
    /^(parse|safeParse|validate|validateAsync)$/i.test(simpleName) ||
    /\b(zod|schema)\b/i.test(callee)
  ) {
    return { type: "validation", label: `Input validation: ${simpleName}`, line, confidence: 0.84 };
  }
  if (/^(rateLimit|ratelimit|throttle|consume)$/i.test(simpleName) || /rate.?limit/i.test(callee)) {
    return { type: "rate-limit", label: "Rate limiting", line, confidence: 0.88 };
  }
  if (
    /^(encrypt|decrypt|createCipheriv|seal)$/i.test(simpleName) ||
    /\b(kms|cipher)\b/i.test(callee)
  ) {
    return { type: "encryption", label: "Encryption control", line, confidence: 0.82 };
  }

  const text = call.getText(source);
  if (
    /\b(allowedTypes|mimeTypes|contentTypes?)\.includes\s*\(/i.test(text) ||
    /\bfile\.(type|mimetype)\b/i.test(text)
  ) {
    return { type: "content-type", label: "Content type allowlist", line, confidence: 0.88 };
  }
  if (
    /\b(ownerId|userId|tenantId|accountId)\b/i.test(text) &&
    /\b(where|filter|find|update|delete)\b/i.test(text)
  ) {
    return { type: "ownership", label: "Resource ownership constraint", line, confidence: 0.81 };
  }
  return null;
}

function classifyOperationCall(
  call: ts.CallExpression,
  source: ts.SourceFile,
  line: number,
  position: number,
  tainted: Set<string>,
  secretIdentifiers: Set<string>
): AstOperation | null {
  const callee = call.expression.getText(source);
  const text = call.getText(source);
  const userControlled = expressionContainsTaint(call, source, tainted);

  const prisma =
    /\b(?:prisma|db)\.([A-Za-z0-9_]+)\.(create|createMany|update|updateMany|delete|deleteMany|upsert|findUnique|findFirst|findMany|count|aggregate|queryRaw|executeRaw)\b/i.exec(
      callee
    );
  if (prisma) {
    const model = prisma[1] ?? "unknown";
    const operation = prisma[2] ?? "query";
    const writes =
      /^(create|createMany|update|updateMany|delete|deleteMany|upsert|executeRaw)$/i.test(
        operation
      );
    return {
      kind: "database",
      edgeKind: writes ? "writes" : "reads",
      label: `Database ${writes ? "write" : "read"}: ${model}.${operation}`,
      trustZone: "data",
      line,
      position,
      metadata: { model, operation, userControlled }
    };
  }

  if (
    /\b(?:PutObjectCommand|UploadPartCommand|CompleteMultipartUploadCommand)\b/.test(text) ||
    /\b(writeFile|createWriteStream|upload)\b/i.test(callee)
  ) {
    return {
      kind: "storage",
      edgeKind: "writes",
      label: "Storage write",
      trustZone: "data",
      line,
      position,
      metadata: { callee, userControlled }
    };
  }
  if (
    /\b(?:GetObjectCommand|HeadObjectCommand)\b/.test(text) ||
    /\b(readFile|createReadStream|download)\b/i.test(callee)
  ) {
    return {
      kind: "storage",
      edgeKind: "reads",
      label: "Storage read",
      trustZone: "data",
      line,
      position,
      metadata: { callee, userControlled }
    };
  }
  if (
    /\b(?:DeleteObjectCommand|DeleteObjectsCommand)\b/.test(text) ||
    /\b(unlink|rm|remove)\b/i.test(callee)
  ) {
    return {
      kind: "storage",
      edgeKind: "writes",
      label: "Storage delete",
      trustZone: "data",
      line,
      position,
      metadata: { callee, destructive: true, userControlled }
    };
  }

  if (/^(fetch|axios\.(get|post|put|patch|delete)|got|request)$/i.test(callee)) {
    const destination = analyzeOutboundDestination(call.arguments[0], source, tainted);
    return {
      kind: "external-service",
      edgeKind: "calls",
      label: destination.label,
      trustZone: "external",
      line,
      position,
      metadata: {
        callee,
        destination: destination.destination,
        userControlled,
        userControlledHost: destination.userControlledHost
      }
    };
  }

  if (
    /\b(child_process\.)?(exec|execFile|spawn|fork|eval)$/i.test(callee) ||
    callee === "Function"
  ) {
    return {
      kind: "component",
      edgeKind: "calls",
      label: "Privileged code or command execution",
      trustZone: "privileged",
      line,
      position,
      metadata: { callee, execution: true, userControlled }
    };
  }

  if (/\b(console\.(log|error|warn)|logger\.(info|error|warn|debug))$/i.test(callee)) {
    return {
      kind: "component",
      edgeKind: "writes",
      label: "Application log sink",
      trustZone: "external",
      line,
      position,
      metadata: {
        callee,
        logging: true,
        userControlled,
        secretReferenced:
          /process\.env|api.?key|secret|token|password/i.test(text) ||
          [...secretIdentifiers].some((name) => containsIdentifier(text, name))
      }
    };
  }

  return null;
}

function collectTaintedIdentifiers(
  node: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
  seed = new Set<string>()
): Set<string> {
  const tainted = new Set(seed);
  for (const parameter of node.parameters) {
    if (
      ts.isIdentifier(parameter.name) &&
      /^(req|request|params|context|ctx)$/i.test(parameter.name.text)
    ) {
      tainted.add(parameter.name.text);
    }
  }

  const assignments: Array<{ names: string[]; expression: ts.Expression }> = [];
  if (node.body) {
    visitScoped(node.body, (current) => {
      if (ts.isVariableDeclaration(current) && current.initializer) {
        assignments.push({ names: bindingNames(current.name), expression: current.initializer });
        return;
      }
      if (
        ts.isBinaryExpression(current) &&
        current.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(current.left)
      ) {
        assignments.push({ names: [current.left.text], expression: current.right });
      }
    });
  }

  let changed = true;
  for (let round = 0; round < 12 && changed; round++) {
    changed = false;
    for (const assignment of assignments) {
      const expression = assignment.expression.getText(source);
      if (
        isRequestSource(expression) ||
        [...tainted].some((name) => containsIdentifier(expression, name))
      ) {
        for (const name of assignment.names) {
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
        }
      }
    }
  }
  return tainted;
}

function expressionContainsTaint(
  node: ts.Node,
  source: ts.SourceFile,
  tainted: Set<string>
): boolean {
  const text = node.getText(source);
  return isRequestSource(text) || [...tainted].some((name) => containsIdentifier(text, name));
}

function isRequestSource(text: string): boolean {
  return /\b(req|request)\.(body|query|params|headers|cookies|file|files|url)\b|\b(request|req)\.(json|formData|text|arrayBuffer)\s*\(|\b(?:req|request)\.nextUrl\b|\b(?:new\s+URL\s*\(\s*(?:req|request)\.url)|\b(searchParams|params)\b/i.test(
    text
  );
}

function containsIdentifier(text: string, identifier: string): boolean {
  return new RegExp(`\\b${escapeRegExp(identifier)}\\b`).test(text);
}

function collectSecretIdentifiers(
  node: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
  seed = new Set<string>()
): Set<string> {
  const identifiers = new Set(seed);
  const assignments: Array<{ names: string[]; expression: ts.Expression }> = [];
  if (!node.body) return identifiers;
  visitScoped(node.body, (current) => {
    if (ts.isVariableDeclaration(current) && current.initializer) {
      assignments.push({ names: bindingNames(current.name), expression: current.initializer });
      return;
    }
    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(current.left)
    ) {
      assignments.push({ names: [current.left.text], expression: current.right });
    }
  });

  let changed = true;
  for (let round = 0; round < 12 && changed; round++) {
    changed = false;
    for (const assignment of assignments) {
      const expression = assignment.expression.getText(source);
      if (
        /process\.env(?:\.|\[|\b)/.test(expression) ||
        [...identifiers].some((name) => containsIdentifier(expression, name))
      ) {
        for (const name of assignment.names) {
          if (!identifiers.has(name)) {
            identifiers.add(name);
            changed = true;
          }
        }
      }
    }
  }
  return identifiers;
}

function taintedParametersForCall(
  call: ts.CallExpression,
  helper: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
  tainted: Set<string>
): Set<string> {
  return seededParametersForCall(call, helper, (argument) =>
    expressionContainsTaint(argument, source, tainted)
  );
}

function secretParametersForCall(
  call: ts.CallExpression,
  helper: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
  secrets: Set<string>
): Set<string> {
  return seededParametersForCall(call, helper, (argument) => {
    const text = argument.getText(source);
    return (
      /process\.env(?:\.|\[|\b)/.test(text) ||
      [...secrets].some((name) => containsIdentifier(text, name))
    );
  });
}

function seededParametersForCall(
  call: ts.CallExpression,
  helper: ts.FunctionLikeDeclaration,
  predicate: (argument: ts.Expression) => boolean
): Set<string> {
  const seeded = new Set<string>();
  helper.parameters.forEach((parameter, index) => {
    const argument = call.arguments[index];
    if (!argument || !predicate(argument)) return;
    for (const name of bindingNames(parameter.name)) seeded.add(name);
  });
  return seeded;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingNames(element.name)
  );
}

interface OutboundDestination {
  destination: string;
  label: string;
  userControlledHost: boolean;
}

function analyzeOutboundDestination(
  node: ts.Expression | undefined,
  source: ts.SourceFile,
  tainted: Set<string>
): OutboundDestination {
  const staticValue = staticString(node);
  if (staticValue) {
    return {
      destination: staticValue,
      label: `External call: ${summarizeDestination(staticValue)}`,
      userControlledHost: false
    };
  }
  if (node && ts.isTemplateExpression(node)) {
    const staticHost = /^https?:\/\/([^/${?#]+)/i.exec(node.head.text)?.[1];
    if (staticHost) {
      return {
        destination: staticHost,
        label: `External call: ${staticHost}`,
        userControlledHost: false
      };
    }
  }
  const userControlledHost = node ? expressionContainsTaint(node, source, tainted) : false;
  return {
    destination: "dynamic",
    label: userControlledHost
      ? "External network call with request-influenced destination"
      : "External network call with dynamic destination",
    userControlledHost
  };
}

function extractSecrets(source: ts.SourceFile): AstSecretUse[] {
  const result: AstSecretUse[] = [];
  visit(source, (node) => {
    const secret = secretUse(node, source);
    if (secret) result.push(secret);
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer?.getText(source) === "process.env"
    ) {
      for (const element of node.name.elements) {
        if (element.dotDotDotToken) continue;
        const property = element.propertyName?.getText(source) ?? element.name.getText(source);
        result.push({ name: property.replace(/["'`]/g, ""), line: lineOf(source, element) });
      }
    }
  });
  return dedupeSecrets(result);
}

function secretUse(node: ts.Node, source: ts.SourceFile): AstSecretUse | null {
  if (ts.isPropertyAccessExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    if (
      node.expression.expression.getText(source) === "process" &&
      node.expression.name.text === "env"
    ) {
      return { name: node.name.text, line: lineOf(source, node) };
    }
  }
  if (ts.isElementAccessExpression(node) && node.expression.getText(source) === "process.env") {
    const name = staticString(node.argumentExpression);
    if (name) return { name, line: lineOf(source, node) };
  }
  return null;
}

function containsExpressCalls(source: ts.SourceFile, receivers: Set<string>): boolean {
  let found = false;
  visit(source, (node) => {
    if (found || !ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression))
      return;
    const method = node.expression.name.text.toUpperCase();
    if (HTTP_METHODS.has(method) && resolveExpressRouteCall(node, source, receivers)) found = true;
  });
  return found;
}

function collectExpressReceivers(source: ts.SourceFile): Set<string> {
  const receivers = new Set(["app", "router"]);
  visit(source, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    if (!ts.isCallExpression(node.initializer)) return;
    const initializer = node.initializer.expression.getText(source);
    if (/^(?:express|Router|express\.Router)$/.test(initializer)) receivers.add(node.name.text);
  });
  return receivers;
}

function isExpressReceiver(value: string, receivers: Set<string>): boolean {
  return receivers.has(value) || /(^|\.)(app|router)$/.test(value);
}

function combineAnalyses(values: HandlerAnalysis[]): HandlerAnalysis {
  return {
    controls: dedupeControls(values.flatMap((value) => value.controls)),
    operations: dedupeOperations(values.flatMap((value) => value.operations)),
    secrets: dedupeSecrets(values.flatMap((value) => value.secrets))
  };
}

function hasExportModifier(node: ts.Node): boolean {
  return Boolean(ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Export);
}

function staticString(node: ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return undefined;
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function visit(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  node.forEachChild((child) => visit(child, callback));
}

function visitScoped(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  node.forEachChild((child) => {
    if (isNestedFunction(child)) return;
    visitScoped(child, callback);
  });
}

function isNestedFunction(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function scriptKindFor(path: string): ts.ScriptKind {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs"))
    return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function lastSegment(value: string): string {
  return (
    value
      .split(".")
      .at(-1)
      ?.replace(/[^A-Za-z0-9_$]/g, "") ?? value
  );
}

function summarizeDestination(value: string): string {
  try {
    return new URL(value).host || value;
  } catch {
    return value.slice(0, 60);
  }
}

function nextRoutePath(path: string): string {
  const normalized = path.replaceAll("\\", "/");
  const appIndex = normalized.indexOf("app/");
  const route = appIndex >= 0 ? normalized.slice(appIndex + 4) : normalized;
  const withoutFile = route.replace(/\/route\.[jt]sx?$/, "");
  const cleaned = withoutFile
    .split("/")
    .filter((segment) => !/^\(.+\)$/.test(segment))
    .map((segment) =>
      segment
        .replace(/^\[\[\.\.\.(.+)\]\]$/, "*$1?")
        .replace(/^\[\.\.\.(.+)\]$/, "*$1")
        .replace(/^\[(.+)\]$/, ":$1")
    )
    .join("/");
  return `/${cleaned}`.replace(/\/$/, "") || "/";
}

function emptyAnalysis(): HandlerAnalysis {
  return { controls: [], operations: [], secrets: [] };
}

function dedupeControls(values: AstControl[]): AstControl[] {
  const map = new Map<string, AstControl>();
  for (const value of values) {
    const key = `${value.type}:${value.label}:${value.sourcePath ?? ""}:${value.line}`;
    const existing = map.get(key);
    if (!existing || value.confidence > existing.confidence) map.set(key, value);
  }
  return [...map.values()].sort((a, b) => a.line - b.line || a.type.localeCompare(b.type));
}

function dedupeOperations(values: AstOperation[]): AstOperation[] {
  const map = new Map<string, AstOperation>();
  for (const value of values)
    map.set(
      `${value.kind}:${value.edgeKind}:${value.position ?? value.line}:${value.label}`,
      value
    );
  return [...map.values()].sort(
    (a, b) => (a.position ?? a.line) - (b.position ?? b.line) || a.label.localeCompare(b.label)
  );
}

function dedupeSecrets(values: AstSecretUse[]): AstSecretUse[] {
  const map = new Map<string, AstSecretUse>();
  for (const value of values) map.set(`${value.name}:${value.line}`, value);
  return [...map.values()].sort((a, b) => a.line - b.line || a.name.localeCompare(b.name));
}

function dedupeEntrypoints(values: AstEntrypoint[]): AstEntrypoint[] {
  const map = new Map<string, AstEntrypoint>();
  for (const value of values)
    map.set(`${value.framework}:${value.method}:${value.path}:${value.line}`, value);
  return [...map.values()].sort((a, b) => a.line - b.line || a.method.localeCompare(b.method));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
