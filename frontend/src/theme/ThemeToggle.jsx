import Icon from "../components/ui/Icon.jsx";
import { useTheme } from "./theme.js";

export default function ThemeToggle() {
  const [theme, setTheme] = useTheme();
  const target = theme === "dark" ? "light" : "dark";
  return (
    <button className="icon-button" aria-label={`Switch to ${target} theme`} title={`Switch to ${target} theme`}
      onClick={() => setTheme(target)}>
      <Icon name={theme === "dark" ? "sun" : "moon"} />
    </button>
  );
}
