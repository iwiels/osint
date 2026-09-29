/** Marca cuál de las cargas de evidencia de CaseView sigue autorizada a escribir. */
export function createCaseLoadGuard() {
  let generation = 0;
  let caseId: string | null = null;

  return {
    begin: (nextCaseId: string) => {
      caseId = nextCaseId;
      return ++generation;
    },
    isCurrent: (request: number, activeCaseId: string) =>
      request === generation && caseId === activeCaseId,
    invalidate: () => {
      generation += 1;
      caseId = null;
    },
  };
}
