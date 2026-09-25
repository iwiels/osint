export {};

declare global {
  interface Window {
    specterDesktop?: {
      platform: string;
      revealInFolder: (fsPath: string) => Promise<boolean>;
    };
  }
}
