/**
 * Sidebar - gestión de casos.
 */

import { useState } from "react";
import type { SpecterClient } from "@specter/sdk";
import { useStore } from "../store";

export default function Sidebar({ client }: { client: SpecterClient }) {
  const cases = useStore((s) => s.cases);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const setActiveCase = useStore((s) => s.setActiveCase);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const createCase = async () => {
    if (!name.trim()) return;
    const created = await client.createCase({
      name: name.trim(),
      description: description.trim() || "Sin descripción",
    });
    useStore.getState().setCases([
      {
        case_id: created.case_id,
        name: created.name,
        description,
        investigator: created.investigator,
        created_at: new Date().toISOString(),
        status: "active",
      },
      ...cases,
    ]);
    setActiveCase(created.case_id);
    setCreating(false);
    setName("");
    setDescription("");
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <span>Casos</span>
        <button className="btn tiny" onClick={() => setCreating(!creating)}>
          {creating ? "×" : "+ Nuevo"}
        </button>
      </div>

      {creating && (
        <div className="case-form">
          <input
            autoFocus
            placeholder="Nombre del caso"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <textarea
            placeholder="Descripción de la investigación"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
          />
          <button className="btn primary small" onClick={createCase}>
            Crear caso (bloque génesis)
          </button>
        </div>
      )}

      <ul className="case-list">
        {cases.map((c) => (
          <li
            key={c.case_id}
            className={`case-item ${c.case_id === activeCaseId ? "active" : ""}`}
            onClick={() => setActiveCase(c.case_id)}
          >
            <div className="case-name">{c.name}</div>
            <div className="case-id">{c.case_id}</div>
          </li>
        ))}
        {cases.length === 0 && !creating && (
          <li className="empty-note">Sin casos aún. Crea el primero.</li>
        )}
      </ul>
    </aside>
  );
}
