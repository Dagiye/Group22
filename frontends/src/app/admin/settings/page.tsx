"use client";

import { useEffect, useState } from "react";
import { getSettings, updateSettings, Settings } from "@/services/settingsService";
import { useToast } from "@/components/ui/use-toast";
import { useAuth } from "@/hooks/useAuths";

export default function SettingsPage() {
  const { user } = useAuth(); // optional: check if admin
  const { addToast } = useToast();

  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Load settings from API
  async function loadSettings() {
    setLoading(true);
    try {
      const data = await getSettings();
      setSettings(data);
    } catch (err: any) {
      addToast({ title: "❌ Failed to load settings", description: err.message });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSettings();
  }, []);

  // Save settings handler
  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await updateSettings(settings);
      setSettings(updated);
      addToast({ title: "✅ Settings updated" });
    } catch (err: any) {
      addToast({ title: "❌ Failed to save settings", description: err.message });
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <p className="p-4">Loading settings...</p>;

  return (
    <div className="p-6 max-w-lg">
      <h1 className="text-xl font-bold mb-4">System Settings</h1>

      <form onSubmit={handleSave} className="space-y-4">
        <div>
          <label className="block font-medium">Scanner Timeout (seconds)</label>
          <input
            type="number"
            value={settings?.scanner_timeout ?? ""}
            disabled={saving}
            onChange={(e) =>
              setSettings((s) =>
                s ? { ...s, scanner_timeout: Number(e.target.value) } : s
              )
            }
            className="border px-2 py-1 w-full"
          />
        </div>

        <div>
          <label className="block font-medium">Max Concurrent Scans</label>
          <input
            type="number"
            value={settings?.max_concurrent_scans ?? ""}
            disabled={saving}
            onChange={(e) =>
              setSettings((s) =>
                s ? { ...s, max_concurrent_scans: Number(e.target.value) } : s
              )
            }
            className="border px-2 py-1 w-full"
          />
        </div>

        <div>
          <label className="block font-medium">Notification Email</label>
          <input
            type="email"
            value={settings?.notify_email ?? ""}
            disabled={saving}
            onChange={(e) =>
              setSettings((s) => (s ? { ...s, notify_email: e.target.value } : s))
            }
            className="border px-2 py-1 w-full"
          />
        </div>

        <button
          type="submit"
          disabled={saving}
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-50"
        >
          {saving ? "Saving..." : "Save Settings"}
        </button>
      </form>
    </div>
  );
}
