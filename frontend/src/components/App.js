import React from "react";
import { createRoot } from "react-dom/client";
import MyRouter from "./Router";

const App = () => {
  return (
    <div>
      <MyRouter />
    </div>
  );
};

const appDiv = document.getElementById("app");
const root = createRoot(appDiv);
root.render(<App />);
