declare global {
  namespace NodeJS {
    interface Process {
      resourcesPath: string;
    }
  }
}

export {};
