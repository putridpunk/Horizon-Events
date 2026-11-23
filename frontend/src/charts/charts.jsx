import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS, Filler, Legend, LinearScale, LineElement,
  PointElement, Tooltip,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";
import { COLORS, SEVERITIES } from "../services/constants.js";

ChartJS.register(ArcElement, BarElement, CategoryScale, Filler, Legend, LinearScale, LineElement, PointElement, Tooltip);

const axis = {
  ticks: { color: COLORS.text, maxTicksLimit: 8 },
  grid: { color: COLORS.grid },
};
const base = { responsive: true, maintainAspectRatio: false };

export function EventsOverTime({ points }) {
  const data = {
    labels: points.map((p) => new Date(p.t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" })),
    datasets: [{
      label: "Events", data: points.map((p) => p.count), borderColor: COLORS.accent,
      backgroundColor: "rgba(41, 211, 255, 0.15)", fill: true, tension: 0.3, pointRadius: 2,
    }],
  };
  return <Line data={data} options={{ ...base, plugins: { legend: { display: false } }, scales: { x: axis, y: { ...axis, beginAtZero: true } } }} />;
}

export function SeverityDoughnut({ items }) {
  const ordered = SEVERITIES.map((s) => items.find((i) => i.severity === s) || { severity: s, count: 0 });
  const data = {
    labels: ordered.map((i) => i.severity),
    datasets: [{ data: ordered.map((i) => i.count), backgroundColor: ordered.map((i) => COLORS[i.severity]), borderColor: "#0d1424", borderWidth: 2 }],
  };
  return <Doughnut data={data} options={{ ...base, cutout: "62%", plugins: { legend: { position: "bottom", labels: { color: COLORS.text } } } }} />;
}

export function HorizontalBars({ items, labelKey = "name", valueKey = "count", color = COLORS.accent }) {
  const data = {
    labels: items.map((i) => i[labelKey]),
    datasets: [{ data: items.map((i) => i[valueKey]), backgroundColor: color, borderRadius: 4 }],
  };
  return <Bar data={data} options={{ ...base, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { ...axis, beginAtZero: true }, y: axis } }} />;
}
