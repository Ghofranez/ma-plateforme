from app.application.services.scanner import run_full_scan

class AnalysisUseCases:

    def __init__(self, analysis_repo):
        self.analysis_repo = analysis_repo

    def analyze(self, url: str, user_email: str):
        rapport = run_full_scan(url)
        status = "failed" if rapport.get("vulnerabilities", {}).get("high", 0) > 0 else "completed"
        self.analysis_repo.create(user_email, url, status, rapport)
        return rapport

    def get_history(self, user_email: str):
        import json
        entries = self.analysis_repo.get_by_user(user_email)
        return [
            {
                "id":      str(e.id),
                "url":     e.url,
                "status":  e.status,
                "date":    e.created_at.strftime("%d %b %Y"),
                "time":    e.created_at.strftime("%H:%M"),
                "summary": json.loads(e.summary) if e.summary else None
            }
            for e in entries
        ]