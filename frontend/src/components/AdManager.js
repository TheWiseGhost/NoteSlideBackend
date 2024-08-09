import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import StorefrontIcon from "@mui/icons-material/Storefront";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import { FaBell, FaUserCircle, FaBars, FaSearch } from "react-icons/fa";
import { useNavigate } from "react-router-dom";

const AdManager = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const [ads, setAds] = useState([]);
  const [editAdId, setEditAdId] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [campaignDetails, setCampaignDetails] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [showEditForm, setShowEditForm] = useState(false);
  const [showEditAdForm, setShowEditAdForm] = useState(false);
  const [campaignTitle, setCampaignTitle] = useState("");
  const [interest, setInterest] = useState("");
  const [budget, setBudget] = useState("");
  const [hasBudget, setHasBudget] = useState(true);
  const [budgetManager, setBudgetManager] = useState(false); // New state for budget manager flag
  const [showAdId, setShowAdId] = useState(null);
  const [showAd, setShowAd] = useState(false);
  const [deleteAdId, setDeleteAdId] = useState(null);
  const [deleteAd, setDeleteAd] = useState(false);

  const interests = [
    "No Interest",
    "Math",
    "Science",
    "Literature",
    "History",
    "Computer Science",
    "Business",
    "Health",
    "Personal growth",
    "Engineering",
    "Psychology",
    "Law",
    "Music",
    "Research",
    "Technology",
  ];

  const user = JSON.parse(localStorage.getItem("business_user"));

  useEffect(() => {
    if (!user) {
      navigate("/business");
    }
  }, []);

  useEffect(() => {
    fetchCampaignsData();
  }, []);

  useEffect(() => {
    if (selectedCampaign) {
      fetchAdsData(selectedCampaign);
      fetchCampaignDetails(selectedCampaign);
      setShowForm(false);
      setShowEditForm(false);
      setShowAd(false);
      setDeleteAd(false);
    }
  }, [selectedCampaign]);

  const fetchAdsData = async (campaignId) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/all_ads/?id=${campaignId}`);
      if (!response.ok) {
        throw new Error("Failed to fetch ads data");
      }
      const data = await response.json();
      setAds(data);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching ads:", error);
      setLoading(false);
    }
  };

  const fetchCampaignsData = async () => {
    try {
      const url = "/api/all_campaigns/";
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_id: user.id }),
      });
      if (!response.ok) {
        throw new Error("Failed to fetch campaigns data");
      }
      const data = await response.json();
      setCampaigns(data);
      if (data.length > 0) {
        setSelectedCampaign(data[0]._id);
      }
    } catch (error) {
      console.error("Error fetching campaigns:", error);
    }
  };

  const fetchCampaignDetails = async (campaignId) => {
    try {
      const response = await fetch(`/api/campaign/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ id: campaignId }),
      });
      if (!response.ok) {
        throw new Error("Failed to fetch campaign details");
      }
      const data = await response.json();
      setCampaignDetails(data);
      setBudgetManager(data.budget_manager);
      setInterest(data.interest);
    } catch (error) {
      console.error("Error fetching campaign details:", error);
    }
  };

  const handleCampaignChange = (event) => {
    setSelectedCampaign(event.target.value);
  };

  const handleNavigation = (path) => {
    navigate(path);
  };

  const handleAddCampaign = async (event) => {
    event.preventDefault();
    const campaignData = {
      title: campaignTitle,
      budget: hasBudget ? budget : 0,
      user_id: user.id,
      interest: interest,
    };
    try {
      const response = await fetch("/api/add_campaign/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(campaignData),
      });
      if (!response.ok) {
        throw new Error("Failed to add campaign");
      }
      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        setShowForm(false);
        window.alert("Campaign Added. Refresh to use your new campaign.");
      }
    } catch (error) {
      console.error("Error adding campaign:", error);
    }
  };

  const handleEditCampaign = async (event) => {
    event.preventDefault();
    const campaignData = {
      id: campaignDetails.id,
      title: campaignTitle,
      budget: hasBudget ? budget : 0,
      interest: interest,
    };
    try {
      const response = await fetch("/api/edit_campaign/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(campaignData),
      });
      if (!response.ok) {
        throw new Error("Failed to edit campaign");
      }
      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        setShowEditForm(false);
        window.alert("Campaign Edited. Refresh to use your new campaign.");
      }
    } catch (error) {
      console.error("Error editing campaign:", error);
    }
  };

  const handleDeleteCampaign = async (event) => {
    event.preventDefault();
    const campaignData = {
      id: campaignDetails.id,
    };
    try {
      const response = await fetch("/api/delete_campaign/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(campaignData),
      });
      if (!response.ok) {
        throw new Error("Failed to edit campaign");
      }
      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        setShowEditForm(false);
        window.alert("Campaign Deleted. Refresh to see updated status.");
      }
    } catch (error) {
      console.error("Error deleting campaign:", error);
    }
  };

  const toggleEditAdForm = (id, currentBudget) => {
    if (editAdId === id) {
      setShowEditAdForm(!showEditAdForm);
    } else {
      setShowEditAdForm(true);
      setEditAdId(id);
      setBudget(currentBudget);
    }
  };

  const toggleShowAd = (id) => {
    if (showAdId === id) {
      setShowAd(!setShowAd);
      setShowAdId(null);
    } else {
      setShowAd(true);
      setShowAdId(id);
    }
  };

  const toggleDeleteAd = (id) => {
    if (deleteAdId === id) {
      setDeleteAd(!setDeleteAd);
      setDeleteAdId(null);
    } else {
      setDeleteAd(true);
      setDeleteAdId(id);
    }
  };

  const handleEditAd = async (event, ad_id) => {
    event.preventDefault();
    const adData = {
      id: ad_id,
      budget: hasBudget ? budget : 0,
    };
    try {
      const response = await fetch("/api/edit_ad/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(adData),
      });
      if (!response.ok) {
        throw new Error("Failed to edit ad");
      }
      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        setShowEditForm(false);
        window.alert("Ad Edited. Refresh to see your new ad.");
      }
    } catch (error) {
      console.error("Error editing ad:", error);
    }
    setEditAdId(null);
  };

  const handleDeleteAd = async (event, ad_id) => {
    event.preventDefault();
    const adData = {
      id: ad_id,
    };
    try {
      const response = await fetch("/api/delete_ad/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(adData),
      });
      if (!response.ok) {
        throw new Error("Failed to delete ad");
      }
      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        setDeleteAd(false);
        window.alert("Ad Deleted. Refresh to see updated status");
      }
    } catch (error) {
      console.error("Error deleting ad:", error);
    }
    setDeleteAdId(null);
  };

  useEffect(() => {
    const fetchCampaign = async () => {
      if (selectedCampaign) {
        fetchCampaignDetails(selectedCampaign);
      }
    };

    fetchCampaign();
  }, [selectedCampaign]);

  return (
    <div className="flex min-h-screen ml-6">
      {/* Sidebar */}
      <div
        className={`fixed top-0 left-0 h-full bg-white shadow-lg transform transition-transform duration-300 ${
          sidebarOpen ? "translate-x-0 w-28" : "-translate-x-32 w-0"
        }`}
      >
        <div className="flex flex-col items-center mt-28 space-y-8">
          <HomeIcon
            onClick={() => handleNavigation("/dashboard")}
            className="w-1/2 text-gray-700 cursor-pointer"
          />
          <CloudUploadIcon
            onClick={() => handleNavigation("/upload")}
            className="w-1/2 text-gray-700 cursor-pointer"
          />
          <BookmarkIcon
            onClick={() => handleNavigation("/favorites")}
            className="w-1/2 text-gray-700 cursor-pointer"
          />
          <BusinessCenterIcon
            onClick={() => handleNavigation("/business")}
            className="w-1/2 text-gray-700 cursor-pointer"
          />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-col flex-1">
        {/* Top Navbar */}
        <div className="flex items-center justify-between pt-8 bg-white p-4 sticky top-0 z-50">
          <div className="flex items-center">
            <FaBars
              className="w-8 h-8 text-gray-700 cursor-pointer"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            />
            <img
              src="../../static/images/NoteSlideLogo.png"
              className="w-8 ml-8"
            />
            <a
              href="/dashboard"
              className="ml-2 font-nats text-2xl font-semibold"
            >
              Note Slide
            </a>
          </div>
          <div className="flex flex-row items-center flex-1 justify-center mr-8">
            <div className="flex items-center rounded-2xl border border-gray-700 border-gray-300-black w-2/5">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleNavigation("/dashboard");
                }}
                className="w-full"
              >
                <input
                  type="text"
                  className="px-4 w-full py-2 rounded-2xl focus:outline-2"
                  placeholder="Search..."
                />
                <button type="submit" className="hidden">
                  Search
                </button>
              </form>
            </div>
            <FaSearch
              onClick={() => handleNavigation("/dashboard")}
              className="cursor-pointer w-6 h-6 text-gray-700 mx-4"
            />
          </div>
          <div className="flex items-center space-x-4 mr-12">
            <FaBell className="w-6 h-6 text-gray-700" />
            <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
              <FaUserCircle
                onClick={() => handleNavigation("/profile")}
                className="w-6 h-6 text-gray-700 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* MainPortal */}
        <div className="p-4 pt-8">
          <div
            className={`flex transform transition-transform duration-1000 ${
              sidebarOpen ? "w-5/6" : "w-11/12"
            } mx-auto items-center mb-8`}
          >
            <h1 className="text-3xl items-center font-alata">
              <BusinessCenterIcon
                onClick={() => handleNavigation("/business_main")}
                className="w-1/2 mr-5 items-center mb-2 text-gray-700 cursor-pointer"
              />
              <StorefrontIcon
                onClick={() => {
                  window.location.reload();
                }}
                className="w-1/2 mr-3 items-center mb-2 text-gray-700 cursor-pointer"
              />
              Ad Manager - {user.name}
            </h1>
            <select
              value={selectedCampaign}
              onChange={handleCampaignChange}
              className="ml-10 select pr-10 pl-6 py-2 font-outfit border border-gray-300 rounded-md bg-gray-200"
            >
              {campaigns.map((campaign) => (
                <option key={campaign._id} value={campaign._id}>
                  {campaign.title}
                </option>
              ))}
            </select>
            <button
              onClick={() => setShowForm(!showForm)}
              className="float-left mr-auto ml-5 bg-gray-200 hover:bg-gray-300 rounded-xl px-3 py-1 text-2xl font-outfit"
            >
              {showForm ? <p>-</p> : <p>+</p>}
            </button>
            <div
              onClick={() => handleNavigation("/uploadad")}
              className="main ml-10 px-6 py-3 text-lg"
            >
              <a href="/uploadad">Upload Ad</a>
            </div>
          </div>

          {/* Add Campaign Form */}
          {showForm && (
            <form
              onSubmit={handleAddCampaign}
              className={`flex flex-col ${
                sidebarOpen ? "w-5/6" : "w-11/12"
              } mx-auto mb-8 p-4 border-2 pl-12 border-gray-400 rounded-lg bg-white`}
            >
              <h2 className="text-2xl font-outfit mb-4">Add New Campaign</h2>
              <div className="mb-4">
                <label className="block text-gray-700 font-outfit mb-2">
                  Campaign Title
                </label>
                <input
                  type="text"
                  value={campaignTitle}
                  onChange={(e) => setCampaignTitle(e.target.value)}
                  className="px-3 py-2 w-2/5 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                  required
                />
              </div>

              <div className="mb-4">
                <label className="block text-gray-700 font-outfit mb-2">
                  Interest
                </label>
                <select
                  onChange={(e) => setInterest(e.target.value)}
                  className="px-3 py-2 w-2/5 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                >
                  {interests.map((interest) => (
                    <option key={interest}>{interest}</option>
                  ))}
                </select>
              </div>

              <div className="mb-4">
                <label className="block text-gray-700 font-outfit mb-2">
                  Campaign Type
                </label>
                <div className="flex items-center">
                  <input
                    type="radio"
                    id="hasBudgetYes"
                    name="hasBudget"
                    value={true}
                    checked={hasBudget}
                    onChange={() => setHasBudget(true)}
                    className="mr-2 font-outfit"
                  />
                  <label htmlFor="hasBudgetYes" className="mr-6 font-outfit">
                    CBO
                  </label>
                  <input
                    type="radio"
                    id="hasBudgetNo"
                    name="hasBudget"
                    value={false}
                    checked={!hasBudget}
                    onChange={() => setHasBudget(false)}
                    className="mr-2 font-outfit"
                  />
                  <label htmlFor="hasBudgetNo" className="font-outfit">
                    ABO
                  </label>
                </div>
                {hasBudget && (
                  <div>
                    <label className="block text-gray-700 font-outfit mt-2">
                      Budget
                    </label>
                    <div className="flex flex-row items-center font-outfit">
                      $
                      <input
                        type="number"
                        value={budget}
                        onChange={(e) => setBudget(e.target.value)}
                        className="px-3 py-2 w-1/6 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                        required
                      />
                      .00
                    </div>
                  </div>
                )}
              </div>
              <button
                type="submit"
                className="px-4 py-2 wipe text-white rounded-lg font-outfit"
              >
                Add Campaign
              </button>
            </form>
          )}

          <div
            className={`flex flex-row justify-between ${
              sidebarOpen ? "w-5/6" : "w-11/12"
            } mx-auto mb-4 `}
          >
            <div className="flex flex-row">
              <h1 className="font-outfit text-gray-800 text-2xl">
                {budgetManager ? (
                  <span className="font-semibold">
                    CBO - ${campaignDetails.spend} / ${campaignDetails.budget}
                  </span>
                ) : (
                  <span className="font-semibold">ABO</span>
                )}{" "}
              </h1>
              <button
                onClick={() => setShowEditForm(!showEditForm)}
                className="bg-gray-200 rounded-xl ml-8 px-3 pt-2 pb-1 text-md font-normal hover:bg-gray-300 text-gray-700 font-josefin"
              >
                {showEditForm ? <p>Close</p> : <p>Edit</p>}
              </button>
            </div>
            <div>
              <h1 className="font-outfit text-gray-800 text-2xl">
                Interest -{" "}
                <span className="font-semibold">
                  {campaignDetails.interest}
                </span>
              </h1>
            </div>
          </div>

          {/* Edit Campaign Form */}
          {showEditForm && (
            <div>
              <form
                onSubmit={handleEditCampaign}
                className={`flex flex-col ${
                  sidebarOpen ? "w-5/6" : "w-11/12"
                } mx-auto mb-8 p-4 pl-12 border-gray-400 border-2 rounded-lg`}
              >
                <h2 className="text-2xl font-outfit mb-4">Edit Campaign</h2>
                <div className="mb-4">
                  <label className="block text-gray-700 font-outfit mb-2">
                    Campaign Title
                  </label>
                  <input
                    type="text"
                    value={campaignTitle}
                    onChange={(e) => setCampaignTitle(e.target.value)}
                    className="px-3 py-2 w-2/5 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                    placeholder={campaignDetails.title}
                    required
                  />
                </div>
                <div className="mb-4">
                  <label className="block text-gray-700 font-outfit mb-2">
                    Interest
                  </label>
                  <select
                    onChange={(e) => setInterest(e.target.value)}
                    className="px-3 py-2 w-2/5 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                    defaultValue={campaignDetails.interest} // Use defaultValue here
                  >
                    <option value="" disabled>
                      {campaignDetails.interest}
                    </option>{" "}
                    {/* Display as placeholder */}
                    {interests.map((interest) => (
                      <option key={interest} value={interest}>
                        {interest}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="mb-4">
                  <label className="block text-gray-700 font-outfit mb-2">
                    Budget Type - (You current use{" "}
                    {budgetManager ? (
                      <span className="font-semibold">CBO</span>
                    ) : (
                      <span className="font-semibold">ABO</span>
                    )}
                    )
                  </label>
                  <div className="flex items-center">
                    <input
                      type="radio"
                      id="hasBudgetYes"
                      name="hasBudget"
                      value={true}
                      checked={hasBudget}
                      onChange={() => setHasBudget(true)}
                      className="mr-2 font-outfit"
                    />
                    <label htmlFor="hasBudgetYes" className="mr-6 font-outfit">
                      CBO
                    </label>
                    <input
                      type="radio"
                      id="hasBudgetNo"
                      name="hasBudget"
                      value={false}
                      checked={!hasBudget}
                      onChange={() => setHasBudget(false)}
                      className="mr-2 font-outfit"
                    />
                    <label htmlFor="hasBudgetNo" className="font-outfit">
                      ABO
                    </label>
                  </div>
                  {hasBudget && (
                    <div>
                      <label className="block text-gray-700 font-outfit mt-2">
                        Budget
                      </label>
                      <div className="flex flex-row items-center font-outfit">
                        $
                        <input
                          type="number"
                          value={budget}
                          onChange={(e) => setBudget(e.target.value)}
                          className="px-3 py-2 w-1/6 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                          placeholder={campaignDetails.budget}
                          required
                        />
                        .00
                      </div>
                    </div>
                  )}
                </div>
                <div className="flex flex-row items-center justify-between">
                  <button
                    type="submit"
                    className="px-4 py-2 w-3/5 wipe text-white rounded-lg font-outfit"
                  >
                    Edit Campaign
                  </button>
                  <button
                    onClick={handleDeleteCampaign}
                    className="px-4 py-2 w-1/5 mt-4 mb-4 mr-10 bg-red-500 text-white rounded-lg font-outfit"
                  >
                    Delete Campaign
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Ads Table */}
          <div
            className={`overflow-x-auto ${
              sidebarOpen ? "w-5/6" : "w-11/12"
            } mx-auto`}
          >
            <table className="min-w-full bg-white border border-gray-300 rounded-lg overflow-hidden">
              <thead className="bg-gray-50 border-b-2 border-gray-300">
                <tr className="text-gray-600 font-outfit uppercase text-sm leading-normal">
                  <th className="py-3 px-6 text-left">Title</th>
                  <th className="py-3 px-6 text-left">Ad Path</th>
                  <th className="py-3 px-6 text-center">Clicks</th>
                  <th className="py-3 px-6 text-center">Views</th>
                  <th className="py-3 px-6 text-center">CTR</th>
                  <th className="py-3 px-6 text-center">CPC</th>
                  <th className="py-3 px-6 text-center">CPM</th>
                  <th className="py-3 px-6 text-center">Spend</th>
                  <th className="py-3 px-6 text-center">Budget</th>
                  <th className="py-3 px-6 text-center">Actions</th>
                </tr>
              </thead>
              <tbody className="text-gray-600 font-outfit text-sm">
                {loading ? (
                  <tr>
                    <td colSpan="10" className="py-4 px-6 text-center">
                      Loading ads...
                    </td>
                  </tr>
                ) : ads.length === 0 ? (
                  <tr>
                    <td colSpan="10" className="py-4 px-6 text-center">
                      No ads found.
                    </td>
                  </tr>
                ) : (
                  ads.map((ad) => (
                    <React.Fragment key={ad._id}>
                      <tr key={`table-row-${ad._id}`} id={ad._id}>
                        <td className="py-3 px-6 text-left whitespace-nowrap">
                          {ad.title}
                        </td>
                        <td className="py-3 px-6 text-left">
                          <button
                            className="text-gray-600 hover:text-gray-900 underline font-outfit"
                            onClick={() => toggleShowAd(ad._id)}
                          >
                            {showAd && showAdId == ad._id ? (
                              <p className="text-red-500 no-underline hover:text-red-700">
                                Close
                              </p>
                            ) : (
                              <p>View Ad</p>
                            )}
                          </button>
                        </td>
                        <td className="py-3 px-6 text-center">{ad.clicks}</td>
                        <td className="py-3 px-6 text-center">{ad.views}</td>
                        <td className="py-3 px-6 text-center">{ad.ctr}</td>
                        <td className="py-3 px-6 text-center">${ad.cpc}</td>
                        <td className="py-3 px-6 text-center">${ad.cpm}</td>
                        <td className="py-3 px-6 text-center">${ad.spend}</td>
                        <td className="py-3 px-6 text-center">
                          {budgetManager ? (
                            <span>CBO</span>
                          ) : (
                            <span>${ad.budget}</span>
                          )}
                        </td>
                        <td className="py-3 px-6 text-center">
                          <button
                            className="text-indigo-600 hover:text-indigo-900 font-outfit"
                            onClick={() => toggleEditAdForm(ad._id, ad.budget)}
                          >
                            {showEditAdForm && editAdId == ad._id ? (
                              <p>Close</p>
                            ) : (
                              <p>Edit</p>
                            )}
                          </button>
                          {" | "}
                          <button
                            onClick={() => toggleDeleteAd(ad._id)}
                            className="text-red-600 hover:text-red-900 font-outfit"
                          >
                            {deleteAd && deleteAdId == ad._id ? (
                              <p>Close</p>
                            ) : (
                              <p>Delete</p>
                            )}
                          </button>
                        </td>
                      </tr>
                      {showEditAdForm && editAdId == ad._id && (
                        <tr key={`edit-form-${ad._id}`}>
                          <td colSpan="10">
                            <form
                              onSubmit={(e) => handleEditAd(e, ad._id)}
                              className={`flex flex-col ${
                                sidebarOpen ? "w-5/6" : "w-11/12"
                              } mx-auto mb-8 p-4 border-2 pl-12 border-gray-400 rounded-lg bg-white`}
                              key={`form-${ad._id}`}
                            >
                              <h2 className="text-2xl font-outfit mb-4">
                                Edit Ad
                              </h2>
                              <div className="mb-4">
                                <label className="block text-gray-700 font-outfit mt-2">
                                  Budget
                                </label>
                                <div className="flex flex-row items-center font-outfit">
                                  $
                                  <input
                                    type="number"
                                    value={budget}
                                    onChange={(e) => setBudget(e.target.value)}
                                    className="px-3 py-2 w-1/6 border border-gray-300 rounded-lg font-outfit focus:outline-none"
                                    required
                                  />
                                  .00
                                </div>
                              </div>
                              <button
                                type="submit"
                                className="self-end px-4 py-2 bg-blue-600 text-white rounded-lg"
                              >
                                Save
                              </button>
                            </form>
                          </td>
                        </tr>
                      )}
                      {deleteAd && deleteAdId == ad._id && (
                        <tr key={`delete-form-${ad._id}`}>
                          <td colSpan="10">
                            <form
                              onSubmit={(e) => handleDeleteAd(e, ad._id)}
                              className={`flex flex-col ${
                                sidebarOpen ? "w-5/6" : "w-11/12"
                              } mx-auto mb-8 p-4 border-2 pl-12 border-gray-400 rounded-lg bg-white`}
                              key={`delete-${ad._id}`}
                            >
                              <h2 className="text-2xl font-outfit mb-4">
                                Delete Ad - Are you sure?
                              </h2>
                              <button
                                type="submit"
                                className="self-end px-4 py-2 bg-red-500 text-white rounded-lg"
                              >
                                Delete
                              </button>
                            </form>
                          </td>
                        </tr>
                      )}
                      {showAd && showAdId == ad._id && (
                        <tr key={`show-ad-${ad._id}`}>
                          <td colSpan="10">
                            <div className="flex-grow flex flex-col items-center justify-center">
                              <div className="flex flex-col items-center justify-center">
                                <video
                                  controls
                                  className="w-4/5 h-auto"
                                  src={ad.s3_path}
                                  type="video/mp4"
                                  muted
                                  autoPlay={true}
                                />
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdManager;
