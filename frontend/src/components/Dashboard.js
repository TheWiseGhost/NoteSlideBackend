import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import NoteView from "./NoteView";
import "../../static/css/index.css";

const Dashboard = () => {
  const navigate = useNavigate();
  const user = JSON.parse(localStorage.getItem("user"));
  useEffect(() => {
    if (!user) {
      navigate("/auth");
    }
  }, []);
  return (
    <div>
      <NoteView />
    </div>
  );
};

export default Dashboard;
