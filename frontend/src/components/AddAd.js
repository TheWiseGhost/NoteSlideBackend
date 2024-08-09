import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import StorefrontIcon from "@mui/icons-material/Storefront";
import { FaBars, FaSearch, FaBell, FaUserCircle } from "react-icons/fa";
import { useNavigate } from "react-router-dom";

const AddAd = () => {
  const MAX_FILE_SIZE_MB = 1024; // 1 GB in MB
  const [selectedFile, setSelectedFile] = useState(null);
  const [title, setTitle] = useState("");
  const [money, setMoney] = useState("");
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState("");
  const [loading, setLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useNavigate();
  const user = JSON.parse(localStorage.getItem("business_user"));

  useEffect(() => {
    if (!user) {
      navigate("/business");
    }
  }, []);

  useEffect(() => {
    const fetchCampaigns = async () => {
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
          throw new Error("Error fetching campaigns");
        }
        const data = await response.json();
        setCampaigns(data);
      } catch (error) {
        console.error("Error fetching campaigns:", error);
      }
    };

    fetchCampaigns();
  }, []);

  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (file) {
      // Check file size
      if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
        // Convert MB to bytes
        alert("File size exceeds 1 GB. Please select a smaller file.");
        setSelectedFile(null); // Clear the file input
      } else {
        setSelectedFile(file);
      }
    }
  };

  const handleTitleChange = (event) => {
    setTitle(event.target.value);
  };

  const handleMoneyChange = (event) => {
    setMoney(event.target.value);
  };

  const handleCampaignChange = (event) => {
    setSelectedCampaign(event.target.value);
  };

  const handleUpload = async () => {
    if (!selectedFile || !title || !money || !selectedCampaign) {
      alert("Please fill all fields and select a file.");
      return;
    }

    setLoading(true);

    try {
      const formData = new FormData();
      formData.append("video_file", selectedFile);
      formData.append("title", title);
      formData.append("money", money);
      formData.append("campaign", selectedCampaign);
      formData.append("user_id", user.id);

      const uploadUrl = "/api/uploadad/";

      const response = await fetch(uploadUrl, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Error uploading file.");
      }

      const data = await response.json();
      if (data.warning) {
        alert(data.warning);
      } else {
        console.log("File uploaded successfully:", data);
        alert("File uploaded successfully!");
        setSelectedFile(null);
        setTitle("");
        setMoney("");
        setSelectedCampaign("");
      }
    } catch (error) {
      console.error("Error uploading file:", error);
      alert("Error uploading file. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    setTitle("");
    setMoney("");
    setSelectedCampaign("");
  };

  const handleNavigation = (path) => {
    navigate(path);
  };

  return (
    <div className="flex h-screen overflow-hidden ml-6">
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
          <div className="flex flex-row items-center flex-1 justify-center mr-12">
            <div className="flex items-center rounded-2xl border border-black w-2/5">
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

        {/* Upload */}
        <div className="w-4/5 justify-between mx-auto p-4 bg-white rounded-lg flex">
          {/* Form Fields */}
          <div className="w-1/2 flex flex-col h-screen pr-16 font-outfit">
            <div className="flex flex-row mb-4">
              <BusinessCenterIcon
                onClick={() => handleNavigation("/business_main")}
                className="w-1/2 mr-5 items-center mb-2 text-gray-700 cursor-pointer"
              />
              <StorefrontIcon
                onClick={() => handleNavigation("/admanager")}
                className="w-1/2 mr-3 items-center mb-2 text-gray-700 cursor-pointer"
              />
            </div>
            <label className="font-medium block mb-2 text-lg">Title</label>
            <input
              type="text"
              value={title}
              onChange={handleTitleChange}
              placeholder="Enter title"
              className="mb-4 px-4 py-2 border border-gray-500 rounded-md"
            />
            <label className="block font-medium mt-4 mb-2 text-lg">
              Budget
            </label>
            <div className="flex flex-row">
              <p className="text-xl pt-2 pr-2 text-gray-600 items-center font-outfit">
                $
              </p>
              <input
                type="number"
                value={money}
                onChange={handleMoneyChange}
                placeholder="Enter budget"
                className="mb-4 w-1/3 px-4 py-2 border border-gray-500 rounded-md"
              />
              <p className="text-xl pt-2 pl-2 text-gray-600 items-center font-outfit">
                .00
              </p>
            </div>
            <div className="mb-8 rounded-md pr-16 mt-4">
              <label className="font-medium block mb-2 text-lg">Campaign</label>
              <select
                value={selectedCampaign}
                onChange={handleCampaignChange}
                className="w-full px-3 py-3 border border-gray-500 rounded-md"
                required
              >
                <option value="" disabled>
                  Select a campaign
                </option>
                {campaigns.map((campaign) => (
                  <option key={campaign._id} value={campaign._id}>
                    {campaign.title}
                  </option>
                ))}
              </select>
            </div>
            <div className="mt-4">
              {loading ? (
                <div className="w-36 mx-auto flex justify-center">
                  <div className="loader"></div>
                </div>
              ) : (
                <div
                  onClick={handleUpload}
                  disabled={
                    !selectedFile || !title || !money || !selectedCampaign
                  }
                  className="main w-36 mx-auto px-8 py-4 text-xl"
                >
                  <a href="#">Create</a>
                </div>
              )}
            </div>
          </div>

          {/* File Upload */}
          <div className="w-1/2 pt-16 flex flex-col items-center">
            {!selectedFile && (
              <label
                htmlFor="file-upload"
                className="flex flex-col w-full items-center justify-center h-60 bg-zinc-100 rounded-2xl border-2 border-dashed border-gray-400 cursor-pointer"
              >
                <CloudUploadIcon style={{ fontSize: 50, color: "gray" }} />
                <span className="mt-2 text-base leading-normal text-gray-600">
                  Drag & drop your video here, or click to select
                </span>
                <input
                  id="file-upload"
                  type="file"
                  className="hidden"
                  accept="video/*"
                  onChange={handleFileChange}
                />
              </label>
            )}
            {selectedFile && (
              <div className="">
                <video
                  controls
                  src={URL.createObjectURL(selectedFile)}
                  className="w-full"
                />
              </div>
            )}
            {selectedFile && (
              <p className="mt-4 font-semibold text-md text-gray-600">
                Selected file: {selectedFile.name}
              </p>
            )}
            {!selectedFile && (
              <p className="mt-4 text-sm text-gray-600">Upload a video ad</p>
            )}
            <div className="mt-4 flex flex-row items-center">
              {selectedFile && (
                <div className="ml-12">
                  <button
                    className="pt-2 pb-1 font-josefin px-4 text-md text-gray-600 border-2 border-gray-600 bg-white hover:text-white hover:bg-gray-600 transition duration-200"
                    onClick={handleClear}
                  >
                    Clear
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddAd;
