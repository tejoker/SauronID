"use client";

import { useEffect, useState } from "react";

// --- Types basés sur ton backend Rust ---
interface UserProfile {
  first_name: string;
  last_name: string;
  email: string;
  age: number;
  country: string;
}

interface UserRecord {
  public_key_hex: string;
  profile: UserProfile | null;
}

interface MemberProfile {
  public_key_hex: string;
  profile: UserProfile | null;
}

interface VerificationRecord {
  timestamp: number;
  message: string;
  ring_size: number;
  ring_members: MemberProfile[];
  is_valid: boolean;
}

export default function Home() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [requests, setRequests] = useState<VerificationRecord[]>([]);
  const [loading, setLoading] = useState(true);

  // Fonction pour raccourcir les clés hexadécimales à l'affichage
  const truncateHex = (hex: string) => {
    if (!hex) return "";
    return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
  };

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const headers = { "x-admin-key": "super_secret_hackathon_key" };
        
        // Appels parallèles aux deux routes de ton API
        const [usersRes, requestsRes] = await Promise.all([
          fetch("http://localhost:3000/admin/users", { headers }),
          fetch("http://localhost:3000/admin/requests", { headers })
        ]);

        if (usersRes.ok && requestsRes.ok) {
          setUsers(await usersRes.json());
          setRequests(await requestsRes.json());
        } else {
          console.error("Erreur d'authentification ou API inaccessible");
        }
      } catch (error) {
        console.error("Erreur de connexion au serveur Sauron:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    
    // Optionnel : Rafraîchissement automatique toutes les 5 secondes
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-black text-black dark:text-white">
        <p className="text-xl font-semibold">Chargement du Dashboard Sauron...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black text-black dark:text-zinc-50 font-sans p-8 sm:p-12">
      <header className="mb-12 border-b border-zinc-200 dark:border-zinc-800 pb-6">
        <h1 className="text-3xl font-bold tracking-tight">Sauron Admin Dashboard</h1>
        <p className="text-zinc-600 dark:text-zinc-400 mt-2">
          Vue en temps réel des identités et des vérifications anonymes (Ring Signatures).
        </p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
        {/* COLONNE 1 : UTILISATEURS INSCRITS */}
        <section>
          <h2 className="text-2xl font-semibold mb-6 flex items-center gap-2">
            Membres du Groupe ({users.length})
          </h2>
          <div className="flex flex-col gap-4">
            {users.length === 0 ? (
              <p className="text-zinc-500 italic">Aucun utilisateur inscrit pour le moment.</p>
            ) : (
              users.map((u, idx) => (
                <div key={idx} className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-xl shadow-sm">
                  {u.profile ? (
                    <>
                      <h3 className="text-lg font-bold">
                        {u.profile.first_name} {u.profile.last_name}
                      </h3>
                      <div className="text-sm text-zinc-600 dark:text-zinc-400 mt-1 flex gap-4">
                        <span>Âge: {u.profile.age} ans</span>
                        <span>Pays: {u.profile.country}</span>
                      </div>
                      <div className="text-xs text-zinc-500 mt-3 bg-zinc-100 dark:bg-black p-2 rounded">
                        Clé Publique: {truncateHex(u.public_key_hex)}
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-zinc-500">Profil incomplet - Clé: {truncateHex(u.public_key_hex)}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </section>

        {/* COLONNE 2 : HISTORIQUE DES REQUÊTES (CERCLES D'ANONYMAT) */}
        <section>
          <h2 className="text-2xl font-semibold mb-6">
            Historique des Requêtes
          </h2>
          <div className="flex flex-col gap-4">
            {requests.length === 0 ? (
              <p className="text-zinc-500 italic">Aucune requête de vérification reçue.</p>
            ) : (
              requests.map((req, idx) => (
                <div key={idx} className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-xl shadow-sm">
                  <div className="flex justify-between items-start mb-3">
                    <span className="text-xs text-zinc-500 font-mono">
                      {new Date(req.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className={`px-2 py-1 text-xs font-bold rounded ${req.is_valid ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                      {req.is_valid ? 'VALIDE' : 'INVALIDE'}
                    </span>
                  </div>
                  
                  <h3 className="text-lg font-medium mb-4">
                    Action : <span className="text-blue-600 dark:text-blue-400">"{req.message}"</span>
                  </h3>

                  <div className="bg-zinc-50 dark:bg-black border border-zinc-200 dark:border-zinc-800 p-4 rounded-lg">
                    <p className="text-sm font-semibold mb-2">
                      Signé par l'un de ces {req.ring_size} membres (Anonymat préservé) :
                    </p>
                    <ul className="list-disc pl-5 space-y-1">
                      {req.ring_members.map((member, mIdx) => (
                        <li key={mIdx} className="text-sm text-zinc-700 dark:text-zinc-300">
                          {member.profile ? 
                            `${member.profile.first_name} ${member.profile.last_name} (${member.profile.age} ans)` 
                            : truncateHex(member.public_key_hex)
                          }
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}