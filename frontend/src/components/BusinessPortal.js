import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import StorefrontIcon from "@mui/icons-material/Storefront";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import WorkIcon from "@mui/icons-material/Work";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import { FaBell, FaUserCircle, FaBars, FaSearch } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
import { useMediaQuery } from "react-responsive";

const BusinessPortal = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(true);
  const navigate = useNavigate();
  const user = JSON.parse(localStorage.getItem("business_user"));
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [domain, setDomain] = useState("");
  const isSmallScreen = useMediaQuery({ query: "(max-width: 600px)" });

  const handleNavigation = (path) => {
    navigate(path);
  };

  const handleLogout = () => {
    localStorage.removeItem("business_user");
    navigate("/business");
  };

  useEffect(() => {
    if (!user) {
      console.log("User not found, redirecting to /business");
      navigate("/business");
    } else {
      setName(user.name);
      setDescription(user.description);
      setDomain(user.domain);
    }

    const fetchStats = async () => {
      try {
        const response = await fetch(`/api/business_stats/`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ user_id: user.id }),
        });
        const data = await response.json();
        setStats(data);
      } catch (error) {
        console.error("Error fetching notes:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  const editBusiness = async (e) => {
    e.preventDefault();
    const data = {
      id: user.id,
      name: name,
      description: description,
      domain: domain,
    };
    try {
      const response = await fetch("/api/edit_business/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error("Failed to edit business");
      }
      window.alert(
        "Business Edited. Logout and Log Back In to use your new business."
      );
    } catch (error) {
      console.error("Error editing business:", error);
    }
  };

  return (
    <div className="flex min-h-screen ml-6">
      {/* Sidebar */}
      <div
        className={`fixed z-50 top-0 left-0 h-full bg-white shadow-lg transform transition-transform duration-300 ${
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
        <div className="flex items-center justify-between pt-8 bg-white p-2 md:p-4 md:pt-8 sticky top-0 z-50">
          <div className="flex items-center">
            <FaBars
              className="w-8 h-8 text-gray-700 cursor-pointer"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            />
            <img
              src="../../static/images/NoteSlideLogo.png"
              className="w-8 ml-4 md:ml-8"
            />
            <a
              href="/dashboard"
              className="ml-2 hidden md:block font-nats text-2xl font-semibold"
            >
              Note Slide
            </a>
          </div>
          <div className="flex flex-row items-center flex-1 justify-center md:mr-12">
            <div className="flex items-center rounded-2xl border border-black w-2/3 md:w-2/5">
              <form
                onSubmit={() => {
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
              onClick={() => {
                handleNavigation("/dashboard");
              }}
              className="cursor-pointer w-6 h-6 text-gray-700 mx-2 md:mx-4"
            />
          </div>
          <div className="flex items-center space-x-2 md:space-x-4 md:mr-12">
            <div className="w-12 h-10 flex items-center justify-center">
              <FaBell className="w-6 h-6 text-gray-700" />
              <div className="font-outfit relative top-0 mb-3 right-0 w-5 h-5 bg-red-500 text-white text-xs font-bold flex items-center justify-center rounded-full">
                <p>{user?.notifs}</p>
              </div>
            </div>

            <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
              <FaUserCircle
                onClick={() => handleNavigation("/profile")}
                className="w-6 h-6 text-gray-700 hover:cursor-pointer cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* MainPortal */}
        <div className="p-4 w-full md:w-4/5 mx-auto">
          {/* Business Information */}
          <div className="flex flex-col md:flex-row justify-between mb-8">
            <div>
              <div
                className={`w-full flex flex-row space-x-12 items-start pt-4`}
              >
                <div className="flex flex-row space-x-4 items-center">
                  <BusinessCenterIcon fontSize="large" />
                  <h1 className="text-4xl font-outfit font-bold">
                    {user?.name}
                  </h1>
                </div>
                <div
                  className="wipe py-2 font-outfit px-4 text-md cursor-pointer"
                  onClick={handleLogout}
                >
                  <a href="" className="">
                    Logout
                  </a>
                </div>
              </div>
              <div className="flex flex-row items-center space-x-4 pt-6">
                <StorefrontIcon
                  onClick={() => handleNavigation("/admanager")}
                  className="w-1/2 text-black cursor-pointer"
                  fontSize="large"
                />
                <a
                  href="/admanager"
                  className="text-black text-xl pt-2 font-josefin hover:underline"
                >
                  Visit Ad Manager{" "}
                  {isSmallScreen ? (
                    <span className="text-red-400">
                      - **Not mobile configured**
                    </span>
                  ) : (
                    <span></span>
                  )}
                </a>
              </div>
            </div>
            <div
              onClick={() => handleNavigation("/buyadcredit")}
              className="main py-6 md:py-0 px-8 my-6 text-xl"
            >
              <a href="">Buy More Ad Credit</a>
            </div>
          </div>

          {/* Ad Metrics */}
          <div className="grid grid-cols-3 gap-8 md:gap-16 mb-8">
            <div className="p-4 rounded pl-6 border-gray-400 border-2">
              <div className="text-lg font-outfit">Ad Credit</div>
              <div className="text-2xl font-josefin font-bold">
                {loading ? (
                  <div className="loader"></div>
                ) : (
                  <p>${stats?.ad_credit}</p>
                )}
              </div>
            </div>
            <div className="p-4 rounded pl-6 border-gray-400 border-2">
              <div className="text-lg font-outfit">Clicks</div>
              <div className="text-2xl font-josefin font-bold">
                {loading ? (
                  <div className="loader"></div>
                ) : (
                  <p>{stats?.clicks}</p>
                )}
              </div>
            </div>
            <div className="p-4 rounded pl-6 border-gray-400 border-2">
              <div className="text-lg font-outfit">Views</div>
              <div className="text-2xl font-josefin font-bold">
                {loading ? (
                  <div className="loader"></div>
                ) : (
                  <p>{stats?.views}</p>
                )}
              </div>
            </div>
          </div>

          {/* Basic Information Form */}
          <div className="border-2 border-gray-400 p-4 rounded font-nats">
            <div className="text-xl font-outfit font-semibold mb-6">
              Basic Information
            </div>
            <form>
              <div className="mb-4">
                <label className="block mb-2">Business Name</label>
                <input
                  type="text"
                  className="border p-2 w-full font-alata"
                  placeholder={user?.name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="mb-4">
                <label className="block mb-2">Description</label>
                <input
                  type="text"
                  className="border p-2 w-full font-alata"
                  placeholder={user?.description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
              <div className="mb-4">
                <label className="block mb-2">
                  Domain (Include https:// - AKA the FULL url)
                </label>
                <input
                  type="text"
                  className="border p-2 w-full font-alata"
                  placeholder={user?.domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </div>
              <div className="mb-4">
                <label className="block mb-2">Payment Info</label>
                <input
                  type="text"
                  className="border p-2 w-full font-alata"
                  placeholder="Payment Info"
                />
              </div>
              <div className="w-3/5 mx-auto">
                <button
                  onClick={(e) => editBusiness(e)}
                  className="wipe w-full justify-center font-josefin p-3 rounded"
                >
                  Update
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BusinessPortal;
