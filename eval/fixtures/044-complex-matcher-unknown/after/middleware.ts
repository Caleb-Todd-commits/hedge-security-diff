export default auth((request: Request) => NextResponse.next());
export const config = { matcher: "/((?!public).*)" };
