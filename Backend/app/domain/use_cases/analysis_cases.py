import json


class AnalysisUseCases:
    def __init__(self, analysis_repo):
        self.analysis_repo = analysis_repo

    def get_history(self, user_email: str):
        """Récupère l'historique des analyses de l'utilisateur"""
        entries = self.analysis_repo.get_by_user(user_email)
        return [
            {
                "id":              str(e.id),
                "url":             e.url,
                "status":          e.status,
                "date":            e.created_at.strftime("%d %b %Y") if e.created_at else None,
                "time":            e.created_at.strftime("%H:%M") if e.created_at else None,
                "summary":         self._normalize_summary(e.summary),
                "full_report":     self._normalize_json(e.full_report),
                "risk_score":      e.risk_score,
                # CORRIGÉ : appel du helper au lieu de la valeur brute
                "recommendations": self._normalize_recommendations(e.recommendations),
            }
            for e in entries
        ]

    # ── HELPERS DE NORMALISATION ───────────────────────────────────────────

    def _normalize_summary(self, value):
        """Toujours retourner une STRING pour éviter crash React"""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            grade = value.get("grade", "N/A")
            risk  = value.get("risk", "N/A")
            return f"Grade: {grade} | Risk: {risk}"
        return str(value)

    def _normalize_json(self, value):
        """Toujours retourner un JSON safe (dict/list)"""
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return {"raw": value}
        return {"value": str(value)}

    def _normalize_recommendations(self, value):
        """Toujours retourner une liste propre pour le frontend"""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            # Si c'est une string avec des sauts de ligne, découper en liste
            lines = [line.strip() for line in value.split("\n") if line.strip()]
            return lines if lines else []
        return [str(value)]

    def delete_entry(self, analysis_id: str, user_email: str):
        """Supprime une analyse si elle appartient bien à l'utilisateur"""
        entry = self.analysis_repo.get_by_id(analysis_id)
        if entry and entry.user_email == user_email:
            return self.analysis_repo.delete(analysis_id)
        return False