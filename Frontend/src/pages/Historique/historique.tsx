import { useState,useEffect } from "react";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import {
  History as HistoryIcon,
  Search,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Calendar,
  Filter
} from "lucide-react";
import { Sidebar, MenuButton } from "../Sidebar/sidebar";
import { getHistory } from "../../services/auth.service";
import toast from "react-hot-toast";
import "./historique.css";

type AnalysisStatus = "completed" | "processing" | "failed";

interface HistoryItem {
  id: string;
  url: string;
  status: AnalysisStatus;
  date: string;
  time: string;
  duration?: string;
  summary?: string;
}

export default function History() {
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<AnalysisStatus | "all">("all");
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const filteredHistory = historyData.filter(item => {
    return (
      item.url.toLowerCase().includes(searchQuery.toLowerCase()) &&
      (filterStatus === "all" || item.status === filterStatus)
    );
  });

  const getStatusIcon = (status: AnalysisStatus) => {
    switch (status) {
      case "completed":
        return <CheckCircle2 className="icon-success" />;
      case "processing":
        return <Loader2 className="icon-loading" />;
      case "failed":
        return <XCircle className="icon-error" />;
    }
  };

  const getStatusText = (status: AnalysisStatus) => {
    switch (status) {
      case "completed": return "Terminé";
      case "processing": return "En cours";
      case "failed": return "Échoué";
    }
  };

  const getStatusClass = (status: AnalysisStatus) => {
    switch (status) {
      case "completed": return "status-success";
      case "processing": return "status-processing";
      case "failed": return "status-error";
    }
  };

useEffect(() => {
  const load = async () => {
    try {
      const data = await getHistory() as any;
      setHistoryData(data); 
    } catch (err) {
      toast.error("Erreur de chargement de l'historique");
    } finally {
      setLoadingHistory(false);
    }
  };
  load();
}, []);


  return (
    <div className="history-container">

      <MenuButton onClick={() => setIsSidebarOpen(true)} />
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

      <div className="history-main">
        <div className="history-wrapper">

          {/* Header */}
          <div className="history-header">
            <h1>Historique des analyses</h1>
            <p>Consultez vos analyses passées</p>
          </div>

          {/* Search */}
          <Card className="card search-card">
            <div className="search-bar">
              <Search className="search-icon" />

              <Input
                placeholder="Rechercher..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />

              <Button onClick={() => setFilterStatus("all")}>
                <Filter /> Tous
              </Button>
            </div>
          </Card>

          {/* List */}
          {loadingHistory ? (
  <Card className="empty"><p>Chargement...</p></Card>
 ) :(
          <div className="history-list">
            {filteredHistory.map((item) => (
              <Card key={item.id} className="history-item">

                <div className="status-icon">
                  {getStatusIcon(item.status)}
                </div>

                <div className="history-content">

                  <a href={item.url} target="_blank" className="url">
                    {item.url}
                    <ExternalLink />
                  </a>

                  <span className={`status ${getStatusClass(item.status)}`}>
                    {getStatusText(item.status)}
                  </span>

                  <div className="meta">
                    <span><Calendar /> {item.date}</span>
                    <span><Clock /> {item.time}</span>
                    {item.duration && <span>{item.duration}</span>}
                  </div>

                  {item.summary && (
                    <p className="summary">{item.summary}</p>
                  )}

                </div>
              </Card>
            ))}

            {filteredHistory.length === 0 && (
              <Card className="empty">
                <HistoryIcon />
                <p>Aucun résultat</p>
              </Card>
            )}
          </div>
 )}
        </div>
      </div>
    </div>
  );
}