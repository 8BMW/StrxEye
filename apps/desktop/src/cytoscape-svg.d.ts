declare module "cytoscape-svg" {
  import type cytoscape from "cytoscape";
  const ext: cytoscape.Ext;
  export default ext;
}

declare namespace cytoscape {
  interface Core {
    svg(options?: { full?: boolean; scale?: number; bg?: string }): string;
  }
}
