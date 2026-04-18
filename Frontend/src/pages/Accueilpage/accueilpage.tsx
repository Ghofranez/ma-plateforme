import { useState, useEffect } from "react";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Card } from "../../components/ui/card";
import {
  Link as LinkIcon,
  ArrowRight,
  Search
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar, MenuButton } from "../Sidebar/sidebar";
import {toast} from "react-hot-toast";
import { analyzeUrl, getHistory } from "../../services/auth.service";
import "./accueil.css";

export default function Home() {
  const [url, setUrl] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [recentUrls, setRecentUrls] = useState<string[]>([]);

  useEffect(() => {
  const loadRecent = async () => {
    try {
      const data = await getHistory() as any[];
      // Prend les 3 dernières URLs analysées
      const last3 = data.slice(0, 3).map((item: any) => item.url);
      setRecentUrls(last3);
    } catch {
      
    }
  };
  loadRecent();
}, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setIsProcessing(true);

    try {
      await analyzeUrl(url);
      setRecentUrls(prev => [url, ...prev.slice(0, 2)]);
      toast.success("Analyse terminée !");
    } catch (err: any) {
      toast.error(err?.detail || "Erreur lors de l'analyse");
    } finally {
      setIsProcessing(false);
      setUrl("");
    }
};

  return (
    <div className="home-container">

      <MenuButton onClick={() => setIsSidebarOpen(true)} />
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

      <div className="main-content">
        <div className="container">

          {/* Header */}
          <div className="header">


            <h1 className="title">Analysez vos contenus</h1>

            <p className="subtitle">
              Insérez une URL pour commencer l'analyse du sécurité
            </p>
          </div>

          {/* Card */}
          <Card className="card">
            <form onSubmit={handleSubmit} className="form">

              <label className="label">URL à analyser</label>

              <div className="input-wrapper">
                <LinkIcon className="input-icon" />
                <Input
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="input"
                  required
                />
              </div>

              <Button
                type="submit"
                disabled={isProcessing || !url.trim()}
                className="submit-btn"
              >
                <AnimatePresence mode="wait">
                  {isProcessing ? (
                    <motion.div key="loading" className="btn-content">
                      <Search className="spin" />
                      Analyse en cours...
                    </motion.div>
                  ) : (
                    <motion.div key="ready" className="btn-content">
                      Analyser
                      <ArrowRight />
                    </motion.div>
                  )}
                </AnimatePresence>
              </Button>

            </form>
          </Card>

          {/* Recent */}
          <div className="recent">
            <h3 className="recent-title">URLs récentes</h3>

            {recentUrls.map((u, i) => (
              <div key={i} className="recent-item" onClick={() => setUrl(u)}>
                <LinkIcon />
                <span>{u}</span>
                <ArrowRight />
              </div>
            ))}
          </div>

        </div>
      </div>
    </div>
  );
}