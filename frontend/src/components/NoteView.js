import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import StorefrontIcon from "@mui/icons-material/Storefront";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import WorkIcon from "@mui/icons-material/Work";
import ThumbUpAltIcon from "@mui/icons-material/ThumbUpAlt";
import VisibilityIcon from "@mui/icons-material/Visibility";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import { FaBell, FaUserCircle, FaBars, FaSearch } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
import { motion, useAnimation } from "framer-motion";
import { useMediaQuery } from "react-responsive";

const NoteView = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [activeSearchTerm, setActiveSearchTerm] = useState("");
  const user = JSON.parse(localStorage.getItem("user"));
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate("/auth");
    }
  }, [user, navigate]);

  useEffect(() => {
    const fetchNotes = async () => {
      setLoading(true); // Ensure loading state is set when fetching data
      try {
        let response;
        if (searchTerm) {
          response = await fetch(
            `/api/search_notes/?search=${encodeURIComponent(searchTerm)}`
          );
        } else {
          response = await fetch("/api/notes/", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ user_id: user.id }),
          });
        }
        const data = await response.json();
        setNotes(data);
        setLoading(false); // Set loading to false after data is fetched
      } catch (error) {
        console.error("Error fetching notes:", error);
        setLoading(false); // Ensure loading state is updated on error as well
      }
    };

    fetchNotes();
  }, [activeSearchTerm]);

  const handleNavigation = (path) => {
    navigate(path);
  };

  const handleNoteClick = (id) => {
    navigate(`/ad/${id}`);
  };

  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
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
        <div className="flex items-center justify-between bg-white pt-8 p-2 md:p-4 md:pt-8 sticky top-0 z-50">
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
                onSubmit={(e) => {
                  e.preventDefault();
                  setActiveSearchTerm(searchTerm);
                }}
                className="w-full"
              >
                <input
                  type="text"
                  className="px-4 w-full py-2 rounded-2xl focus:outline-2"
                  placeholder="Search..."
                  value={searchTerm}
                  onChange={handleSearchChange}
                />
                <button type="submit" className="hidden">
                  Search
                </button>
              </form>
            </div>
            <FaSearch
              onClick={() => {
                setActiveSearchTerm(searchTerm);
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

        {/* Notes */}
        <div className="flex flex-col">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-2xl pt-40 font-outfit">
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
          ) : (
            <div
              className={`mr-0 mt-8 ${
                sidebarOpen ? "ml-32 mr-0" : "ml-12"
              } pt-6 pb-20 min-h-screen bg-white flex flex-wrap`}
              style={{ gap: "48px" }} // Add gap between items
            >
              {notes.map((note) => (
                <NoteCard
                  key={note._id}
                  note={note}
                  onClick={() => handleNoteClick(note._id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const NoteCard = ({ note, onClick }) => {
  const isSmallScreen = useMediaQuery({ query: "(max-width: 600px)" });
  const controls = useAnimation();

  const formatTextWithHyphens = (text, chunkSize = 15) => {
    // Split the text by spaces
    const segments = text.split(" ");

    // Map over segments and format only those that are long enough
    const formattedSegments = segments.map((segment) => {
      if (segment.length >= chunkSize) {
        return segment.split("").reduce((acc, char, index) => {
          if (index > 0 && index % chunkSize === 0) {
            acc += "-";
          }
          acc += char;
          return acc;
        }, "");
      }
      return segment;
    });

    // Join segments back with spaces
    return formattedSegments.join(" ");
  };

  return (
    <motion.div
      onClick={onClick}
      style={{
        flex: isSmallScreen ? "0 1 90%" : "0 1 calc(25% - 48px)",
        minWidth: isSmallScreen ? "" : "200px",
        zIndex: 1, // Ensure it's above the background card
      }}
      className="relative cursor-pointer bg-zinc-300 h-60"
      onHoverStart={() => controls.start({ x: 0, y: 0 })}
      onHoverEnd={() => controls.start({ x: -10, y: -10 })}
    >
      <motion.div
        className="w-full absolute border-4 h-60 border-zinc-600 bg-white p-5 flex flex-col justify-center items-center transition-all duration-100 ease-linear"
        animate={controls}
        initial={{ x: -10, y: -10 }}
      >
        <h3 className="text-center text-xl md:text-2xl font-medium font-outfit mb-2">
          {formatTextWithHyphens(note?.title || "")}
        </h3>
        <p className="text-center mb-1 font-outfit">{note?.username}</p>

        <div className="flex flex-row w-full mx-4 items-end mb-1 mt-auto">
          <div className="flex flex-row items-center justify-start w-1/2 space-x-0">
            <div className="flex w-1/2 mr-5">
              <span className="flex items-center ">
                <VisibilityIcon fontSize="small" />
                <span className="ml-1 font-outfit">{note?.views}</span>
              </span>
            </div>
            <div className="items-center w-1/2 flex">
              <span className="flex items-center">
                <ThumbUpAltIcon fontSize="small" />
                <span className="ml-1 font-outfit">{note?.likes}</span>
              </span>
            </div>
          </div>
          <div className="items-end w-1/2 justify-end flex pt-3">
            <p className="text-center flex font-outfit">{note?.created_at}</p>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default NoteView;
