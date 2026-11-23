import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS, Filler, Legend, LinearScale, LineElement,
  PointElement, Tooltip,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";
import { SEVERITIES } from "../services/constants.js";
import useChartColors from "../theme/useChartColors.js";

ChartJS.register(ArcElement, BarElement, CategoryScale, Filler, Legend, LinearScale, LineElement, PointElement, Tooltip);

const base = { responsive: true, maintainAspectRatio: false };

/** Add transparency to a #rrggbb colour (used for the soft fill under the line). */
const withAlpha = (hex, alpha) => `${hex}${Math.round(alpha * 255).toString(16).padStart(2, "0")}`;

function useAxis() {
  const c = useChartColors();
  return { c, axis: { ticks: { color: c.text, maxTicksLimit: 8 }, grid: { color: c.grid } } };
}

export function EventsOverTime({ points }) {
  const { c, axis } = useAxis();
  const data = {
    labels: points.map((p) => new Date(p.t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" })),
    datasets: [{
      label: "Events", data: points.map((p) => p.count), borderColor: c.accent,
      backgroundColor: withAlpha(c.accent, 0.12), fill: true, tension: 0.2, pointRadius: 2,
    }],
  };
  return <Line data={data} options={{ ...base, plugins: { legend: { display: false } }, scales: { x: axis, y: { ...axis, beginAtZero: true } } }} />;
}

export function SeverityDoughnut({ items }) {
  const { c } = useAxis();
  const ordered = SEVERITIES.map((s) => items.find((i) => i.severity === s) || { severity: s, count: 0 });
  const data = {
    labels: ordered.map((i) => i.severity),
    datasets: [{ data: ordered.map((i) => i.count), backgroundColor: ordered.map((i) => c[i.severity]),
      borderColor: c.surface, borderWidth: 2 }],
  };
  return <Doughnut data={data} options={{ ...base, cutout: "62%", plugins: { legend: { position: "bottom", labels: { color: c.text } } } }} />;
}

/** `tone` is a theme colour name: accent, critical, high, medium or low. */
export function HorizontalBars({ items, labelKey = "name", valueKey = "count", tone = "accent" }) {
  const { c, axis } = useAxis();
  const data = {
    labels: items.map((i) => i[labelKey]),
    datasets: [{ data: items.map((i) => i[valueKey]), backgroundColor: c[tone] ?? c.accent, borderRadius: 0 }],
  };
  return <Bar data={data} options={{ ...base, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { ...axis, beginAtZero: true }, y: axis } }} />;
}
