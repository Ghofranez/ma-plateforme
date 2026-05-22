import { useState, useEffect } from "react";
import {
  Search,
  Users,
  Loader2,
  Mail,
  Phone,
  User,
  ShieldCheck,
} from "lucide-react";
import { getAdminUsers } from "../../services/auth.service";
import toast from "react-hot-toast";

interface UserItem {
  nom: string;
  prenom: string;
  email: string;
  telephone: string;
}

export default function AdminUsers() {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const res = await getAdminUsers();
        const data = Array.isArray(res) ? res : (res as any).data || [];
        setUsers(data);
      } catch {
        toast.error("Accès refusé ou erreur serveur");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = users.filter((u) => {
    const q = searchQuery.toLowerCase();
    return (
      u.nom.toLowerCase().includes(q) ||
      u.prenom.toLowerCase().includes(q) ||
      u.email.toLowerCase().includes(q) ||
      u.telephone.includes(q)
    );
  });

  return (
    <div className="min-h-screen bg-slate-50 pb-12">

      {/* ── Header sticky ── */}
      <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-6 py-3 flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-indigo-100 flex items-center justify-center shrink-0">
          <ShieldCheck size={18} className="text-indigo-600" />
        </div>
        <div className="flex-1">
          <h1 className="font-black text-gray-900 text-base leading-tight">
            Gestion des utilisateurs
          </h1>
          <p className="text-xs text-gray-400">
            {users.length} utilisateur(s) enregistré(s)
          </p>
        </div>
      </div>

      {/* ── Contenu ── */}
      <div className="px-6 mt-5 max-w-3xl mx-auto">

        {/* Recherche */}
        <div className="relative mb-5">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            className="w-full pl-9 pr-4 py-2.5 text-sm bg-white border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 transition"
            placeholder="Rechercher par nom, email, téléphone..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Liste */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="animate-spin text-indigo-500" size={28} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-gray-400">
            <Users size={40} className="mb-3 opacity-40" />
            <p className="text-sm font-medium">Aucun utilisateur trouvé</p>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {filtered.map((user, index) => (
              <div
                key={index}
                className="bg-white rounded-2xl border border-gray-100 shadow-sm hover:shadow-md transition-all overflow-hidden"
                style={{ borderLeft: "4px solid #6366f1" }}
              >
                <div className="p-4">
                  <div className="flex items-start gap-3">

                    {/* Avatar */}
                    <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center shrink-0">
                      <User size={18} className="text-indigo-500" />
                    </div>

                    {/* Infos */}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-black text-gray-800 mb-1">
                        {user.prenom} {user.nom}
                      </p>
                      <div className="flex flex-col gap-1">
                        <span className="flex items-center gap-1.5 text-xs text-gray-500">
                          <Mail size={11} className="text-indigo-400" />
                          {user.email}
                        </span>
                        <span className="flex items-center gap-1.5 text-xs text-gray-500">
                          <Phone size={11} className="text-indigo-400" />
                          {user.telephone}
                        </span>
                      </div>
                    </div>

                    {/* Badge */}
                    <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-indigo-50 border border-indigo-200 text-indigo-600 shrink-0">
                      Utilisateur
                    </span>

                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}