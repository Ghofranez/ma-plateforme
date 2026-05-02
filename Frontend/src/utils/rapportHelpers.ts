//Convertit n'importe quoi (string, array, null) en tableau propre
// ── Helper : parse les recommandations depuis la DB ou depuis full_report ──
export function parseRecs(value: any): string[] {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === "string")
    return value.split("\n").filter((r: string) => r.trim());
  return [];
}

//Lit le tag [Critique], [OK]... et retourne une classe CSS correspondante pour la couleur.
// ── Helper : badge niveau ──────────────────────────────────────────────────
export function getLevel(rec: string) {
  if (rec.startsWith("[Critique]")) return "critique";
  if (rec.startsWith("[Important]")) return "important";
  if (rec.startsWith("[Modéré]"))   return "modere";
  if (rec.startsWith("[OK]"))       return "ok";
  if (rec.startsWith("[Erreur]"))   return "erreur";
  return "default";
}

//Extrait le mot entre crochets [Critique] → "Critique" pour l'afficher dans le badge.
export function getLabel(rec: string) {
  const m = rec.match(/^\[(.+?)\]/);
  return m ? m[1] : "";
}

//Supprime le tag [Critique] du début pour afficher seulement le texte de la recommandation.
export function getText(rec: string) {
  return rec.replace(/^\[.+?\]\s*/, "");
}