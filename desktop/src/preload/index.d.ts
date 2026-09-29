export {};

declare global {
  interface Window {
    wraithDesktop?: {
      platform: string;
      revealInFolder: (fsPath: string) => Promise<boolean>;
    };
  }
}
