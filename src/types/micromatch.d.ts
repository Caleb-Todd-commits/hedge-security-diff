declare module "micromatch" {
  export interface MicromatchOptions {
    basename?: boolean;
    dot?: boolean;
    nocase?: boolean;
    nonegate?: boolean;
  }

  export interface Micromatch {
    isMatch(
      value: string,
      patterns: string | readonly string[],
      options?: MicromatchOptions
    ): boolean;
  }

  const micromatch: Micromatch;
  export default micromatch;
}
