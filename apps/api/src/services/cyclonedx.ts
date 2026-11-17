import { z } from "zod";

const componentSchema = z.object({
  type: z.string().min(1),
  name: z.string().min(1),
  version: z.string().optional(),
  "bom-ref": z.string().optional(),
  purl: z.string().optional(),
}).passthrough();

const bomSchema = z.object({
  bomFormat: z.literal("CycloneDX"),
  specVersion: z.string().regex(/^1\.[2-7]$/),
  serialNumber: z.string().optional(),
  metadata: z.object({ component: componentSchema.optional() }).passthrough().optional(),
  components: z.array(componentSchema).default([]),
  dependencies: z.array(z.object({ ref: z.string(), dependsOn: z.array(z.string()).default([]) }).passthrough()).default([]),
}).passthrough();

export type CycloneDxBom = z.infer<typeof bomSchema>;

export function validateCycloneDx(value: unknown): CycloneDxBom {
  const bom = bomSchema.parse(value);
  const refs = new Set<string>();
  for (const component of bom.components) {
    const ref = component["bom-ref"];
    if (ref && refs.has(ref)) throw new Error(`CycloneDX contains duplicate bom-ref: ${ref}`);
    if (ref) refs.add(ref);
  }
  const metadataRef = bom.metadata?.component?.["bom-ref"];
  if (metadataRef) {
    if (refs.has(metadataRef)) throw new Error(`CycloneDX metadata component duplicates bom-ref: ${metadataRef}`);
    refs.add(metadataRef);
  }
  for (const dependency of bom.dependencies) {
    if (!refs.has(dependency.ref)) throw new Error(`CycloneDX dependency references unknown component: ${dependency.ref}`);
    for (const child of dependency.dependsOn) if (!refs.has(child)) throw new Error(`CycloneDX dependency references unknown target: ${child}`);
  }
  return bom;
}
