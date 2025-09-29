import apiClient from "./client";

/**
 * Export scan report in given format (pdf or csv)
 * and automatically trigger download in browser.
 */
export async function exportReport(scanId: string, format: "pdf" | "csv") {
  try {
    const response = await apiClient.get(`/scans/${scanId}/report`, {
      params: { format },
      responseType: "blob", // important for file download
    });

    // Create a download link for the blob
    const blob = new Blob([response.data], {
      type: format === "pdf" ? "application/pdf" : "text/csv",
    });

    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `scan-${scanId}.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();

    // Release memory
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error(`Failed to export report (${format})`, error);
    alert("⚠️ Failed to export report. See console for details.");
  }
}
