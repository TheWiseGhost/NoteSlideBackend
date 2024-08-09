import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import LandingPage from "./LandingPage";
import Dashboard from "./Dashboard";
import AddNote from "./AddNote";
import ViewNote from "./ViewNote";
import ViewAd from "./ViewAd";
import AddAd from "./AddAd";
import BusinessPortal from "./BusinessPortal";
import AdManager from "./AdManager";
import Auth from "./Auth";
import BusinessAuth from "./BusinessAuth";
import Profile from "./Profile";
import FavoriteNotes from "./FavoriteNotes";
import BuyAdCredit from "./BuyAdCredit";
import VerifyEmail from "./VerifyEmail";
import VerifyBusiness from "./VerifyBusiness";
import PublicProfile from "./PublicProfile";

const MyRouter = () => {
  return (
    <Router>
      <Routes>
        <Route path="/landing/" element={<LandingPage />} />
        <Route path="/" element={<Dashboard />} />
        <Route path="/auth/" element={<Auth />} />
        <Route path="/dashboard/" element={<Dashboard />} />
        <Route path="/upload/" element={<AddNote />} />
        <Route path="/view/:id/" element={<ViewNote />} />
        <Route path="/ad/:id/" element={<ViewAd />} />
        <Route path="/business_main/" element={<BusinessPortal />} />
        <Route path="/business/" element={<BusinessAuth />} />
        <Route path="/uploadad/" element={<AddAd />} />
        <Route path="/admanager/" element={<AdManager />} />
        <Route path="/profile/" element={<Profile />} />
        <Route path="/favorites/" element={<FavoriteNotes />} />
        <Route path="/buyadcredit/" element={<BuyAdCredit />} />
        <Route path="/verify/:token/" element={<VerifyEmail />} />
        <Route path="/verify_business/:token/" element={<VerifyBusiness />} />
        <Route path="/public_profile/:username/" element={<PublicProfile />} />
      </Routes>
    </Router>
  );
};

export default MyRouter;
