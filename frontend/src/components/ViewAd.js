import React, { useState, useEffect, useRef } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import { FaBars, FaSearch, FaBell, FaUserCircle } from "react-icons/fa";
import { useNavigate, useParams } from "react-router-dom";

const ViewAd = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [adUrl, setAdUrl] = useState("");
  const [adId, setAdId] = useState("");
  const [adDomain, setAdDomain] = useState("");
  const [showViewNoteButton, setShowViewNoteButton] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState(5);
  const navigate = useNavigate();
  const { id } = useParams();

  const user = JSON.parse(localStorage.getItem("user"));
  useEffect(() => {
    if (!user) {
      navigate("/auth");
    }
  }, []);

  useEffect(() => {
    const fetchAdUrl = async () => {
      try {
        const response = await fetch(`/api/random_ad/${id}/`);
        const data = await response.json();
        const parsedData = JSON.parse(data); // Parse the JSON string to an object
        if (parsedData.s3_path) {
          setAdUrl(parsedData.s3_path);
          setAdId(parsedData._id.$oid); // Extract ObjectId from nested structure
          if (parsedData.domain) {
            setAdDomain(parsedData.domain);
          }
        } else {
          console.error("Invalid ad URL format");
          console.log(parsedData.s3_path);
        }
      } catch (error) {
        console.error("Error fetching ad URL:", error);
      }
    };
    fetchAdUrl();
  }, []);

  useEffect(() => {
    if (adId) {
      const intervalId = setInterval(() => {
        setTimeRemaining((prevTime) => {
          if (prevTime <= 1) {
            clearInterval(intervalId);
            setShowViewNoteButton(true);
            decreaseAdMoney(adId);
            return 0;
          }
          return prevTime - 1;
        });
      }, 1000);

      return () => clearInterval(intervalId);
    }
  }, [adId]);

  const handleNavigation = (path) => {
    navigate(path);
  };

  const handleVisitBusiness = () => {
    increaseAdClicks(adId);
    if (adDomain) {
      const url =
        adDomain.startsWith("http://") || adDomain.startsWith("https://")
          ? adDomain
          : `https://${adDomain}`;
      window.open(url, "_blank");
    } else {
      window.alert("No URL has been provided for this business");
    }
  };

  const handleViewNote = () => {
    navigate(`/view/${id}`);
  };

  const decreaseAdMoney = async (adId) => {
    try {
      const response = await fetch(`/api/decrease_money/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ id: adId }),
      });
      if (!response.ok) {
        console.error("Error decreasing money");
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };

  const increaseAdClicks = async (adId) => {
    try {
      const response = await fetch(`/api/update_ad_clicks/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ id: adId }),
      });
      if (!response.ok) {
        console.error("Error updating ad clicks");
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };

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
        {/* Main Section */}
        <div className="flex-grow flex flex-col items-center justify-center">
          {adUrl ? (
            <div className="flex flex-col items-center justify-center">
              <video
                controls
                className="w-full md:w-4/5 h-auto pointer-events-none"
                src={adUrl}
                type="video/mp4"
                autoPlay={true}
              />
              <div className="flex flex-row justify-between w-11/12 md:w-4/5 mx-auto">
                <button
                  onClick={handleVisitBusiness}
                  className="bg-amber-300 hover:bg-amber-400 mt-4 px-4 py-2 font-alata"
                >
                  Check it out
                </button>
                {showViewNoteButton ? (
                  <button
                    onClick={handleViewNote}
                    className="mt-4 px-4 py-2 wipe"
                    style={{ alignSelf: "center" }}
                  >
                    View Note
                  </button>
                ) : (
                  <div className="mt-4 px-4 py-2 text-center">
                    View Note in {timeRemaining}s
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-2xl pt-0 font-outfit">
                <div className="flex items-center justify-center h-full">
                  <div className="text-2xl pt-10 font-outfit">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      height="200px"
                      width="200px"
                      viewBox="0 0 200 200"
                      class="pencil"
                    >
                      <defs>
                        <clipPath id="pencil-eraser">
                          <rect height="30" width="30" ry="5" rx="5"></rect>
                        </clipPath>
                      </defs>
                      <circle
                        transform="rotate(-113,100,100)"
                        stroke-linecap="round"
                        stroke-dashoffset="439.82"
                        stroke-dasharray="439.82 439.82"
                        stroke-width="2"
                        stroke="currentColor"
                        fill="none"
                        r="70"
                        class="pencil__stroke"
                      ></circle>
                      <g transform="translate(100,100)" class="pencil__rotate">
                        <g fill="none">
                          <circle
                            transform="rotate(-90)"
                            stroke-dashoffset="402"
                            stroke-dasharray="402.12 402.12"
                            stroke-width="30"
                            stroke="hsl(223,90%,50%)"
                            r="64"
                            class="pencil__body1"
                          ></circle>
                          <circle
                            transform="rotate(-90)"
                            stroke-dashoffset="465"
                            stroke-dasharray="464.96 464.96"
                            stroke-width="10"
                            stroke="hsl(223,90%,60%)"
                            r="74"
                            class="pencil__body2"
                          ></circle>
                          <circle
                            transform="rotate(-90)"
                            stroke-dashoffset="339"
                            stroke-dasharray="339.29 339.29"
                            stroke-width="10"
                            stroke="hsl(223,90%,40%)"
                            r="54"
                            class="pencil__body3"
                          ></circle>
                        </g>
                        <g
                          transform="rotate(-90) translate(49,0)"
                          class="pencil__eraser"
                        >
                          <g class="pencil__eraser-skew">
                            <rect
                              height="30"
                              width="30"
                              ry="5"
                              rx="5"
                              fill="hsl(223,90%,70%)"
                            ></rect>
                            <rect
                              clip-path="url(#pencil-eraser)"
                              height="30"
                              width="5"
                              fill="hsl(223,90%,60%)"
                            ></rect>
                            <rect
                              height="20"
                              width="30"
                              fill="hsl(223,10%,90%)"
                            ></rect>
                            <rect
                              height="20"
                              width="15"
                              fill="hsl(223,10%,70%)"
                            ></rect>
                            <rect
                              height="20"
                              width="5"
                              fill="hsl(223,10%,80%)"
                            ></rect>
                            <rect
                              height="2"
                              width="30"
                              y="6"
                              fill="hsla(223,10%,10%,0.2)"
                            ></rect>
                            <rect
                              height="2"
                              width="30"
                              y="13"
                              fill="hsla(223,10%,10%,0.2)"
                            ></rect>
                          </g>
                        </g>
                        <g
                          transform="rotate(-90) translate(49,-30)"
                          class="pencil__point"
                        >
                          <polygon
                            points="15 0,30 30,0 30"
                            fill="hsl(33,90%,70%)"
                          ></polygon>
                          <polygon
                            points="15 0,6 30,0 30"
                            fill="hsl(33,90%,50%)"
                          ></polygon>
                          <polygon
                            points="15 0,20 10,10 10"
                            fill="hsl(223,10%,10%)"
                          ></polygon>
                        </g>
                      </g>
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ViewAd;
