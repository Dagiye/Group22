"use client";
import { useEffect, useState } from "react";
import { getSettings, updateSettings, Settings } from "@/services/settingsService";

export default function NotificationsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getSettings().then(setSettings);
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await updateSettings({ notify_email: settings.notify_email });
      setSettings(updated);
      alert("✅ Notification email updated");
    } finally {
      setSaving(false);
    }
  }

  if (!settings) return <p className="p-4">Loading...</p>;

  return (
    <div className="p-6 max-w-lg">
      <h1 className="text-xl font-bold mb-4">📧 Email Notifications</h1>
      <form onSubmit={handleSave} className="space-y-4">
        <div>
          <label className="block font-medium">Notify Email</label>
          <input
            type="email"
            value={settings.notify_email}
            onChange={(e) =>
              setSettings((s) => (s ? { ...s, notify_email: e.target.value } : s))
            }
            className="border px-2 py-1 w-full"
          />
        </div>
        <button
          type="submit"
          disabled={saving}
          className="bg-blue-600 text-white px-4 py-2 rounded"
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </form>
    </div>
  );
}
