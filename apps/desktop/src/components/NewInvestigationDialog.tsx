import { useState } from "react";
import { api } from "../api";
import { useApp } from "../App";
import { navigate } from "../lib";
import { ErrorBanner, Modal } from "./ui";

export function NewInvestigationDialog({ onClose }: { onClose: () => void }) {
  const { reloadInvestigations } = useApp();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const inv = await api.createInvestigation(name, description);
      reloadInvestigations();
      onClose();
      navigate({ page: "investigation", id: inv.id, tab: "collect" });
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal title="New investigation" onClose={onClose}>
      <form onSubmit={submit} className="space-y-3">
        <label className="block space-y-1">
          <span className="label">Name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={200}
            placeholder="e.g. Phishing infrastructure – October" required />
        </label>
        <label className="block space-y-1">
          <span className="label">Scope and notes (optional)</span>
          <textarea className="input min-h-20" value={description} onChange={(e) => setDescription(e.target.value)}
            maxLength={5000} placeholder="What you are investigating and under what authorisation." />
        </label>
        {error && <ErrorBanner message={error} />}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={busy || !name.trim()}>Create</button>
        </div>
      </form>
    </Modal>
  );
}
