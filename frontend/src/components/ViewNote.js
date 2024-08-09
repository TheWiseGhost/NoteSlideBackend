import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import StorefrontIcon from "@mui/icons-material/Storefront";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import BookmarkAddTwoToneIcon from "@mui/icons-material/BookmarkAddTwoTone";
import BookmarkRemoveTwoToneIcon from "@mui/icons-material/BookmarkRemoveTwoTone";
import ThumbUpOffAltIcon from "@mui/icons-material/ThumbUpOffAlt";
import ThumbUpAltIcon from "@mui/icons-material/ThumbUpAlt";
import VisibilityIcon from "@mui/icons-material/Visibility";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import { FaBars, FaSearch, FaBell, FaUserCircle } from "react-icons/fa";
import { useNavigate, useParams } from "react-router-dom";
import { useMediaQuery } from "react-responsive";

const ViewNote = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [note, setNote] = useState(null);
  const [likeLoading, setLikeLoading] = useState(false);
  const [favLoading, setFavLoading] = useState(false);
  const navigate = useNavigate();
  const { id } = useParams();
  const user = JSON.parse(localStorage.getItem("user"));
  const isSmallScreen = useMediaQuery({ query: "(max-width: 600px)" });

  useEffect(() => {
    if (!user) {
      navigate("/auth");
    }
  }, []);

  useEffect(() => {
    // Fetch the note by ID
    const fetchNote = async () => {
      try {
        const response = await fetch(`/api/note/${id}/`, {
          method: "POST", // or the appropriate HTTP method
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ user_id: user.id }),
        });
        const data = await response.json();
        setNote(data);
      } catch (error) {
        console.error("Error fetching note:", error);
      }
    };
    fetchNote();
  }, [id]);

  const handleNavigation = (path) => {
    navigate(path);
  };

  const updateLike = async (like) => {
    try {
      setLikeLoading(true);
      const response = await fetch(`/api/note/${id}/like/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_id: user.id, liked: like }),
      });
      const data = await response.json();
      setNote((prevNote) => ({
        ...prevNote,
        likes: data.likes,
        liked: data.liked,
      }));
    } catch (error) {
      console.error("Error toggling like:", error);
    } finally {
      setLikeLoading(false);
    }
  };

  const updateFavorite = async (favorite) => {
    try {
      setFavLoading(true);
      const response = await fetch(`/api/note/${id}/favorite/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_id: user.id, favorite: favorite }),
      });
      const data = await response.json();
      setNote((prevNote) => ({ ...prevNote, favorite: data.favorite }));
    } catch (error) {
      console.error("Error updating favorite:", error);
    } finally {
      setFavLoading(false);
    }
  };

  const handleViewProfile = () => {
    navigate(`/public_profile/${note.username}`);
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
        <div className="flex-grow">
          {!note ? (
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
          ) : (
            <div className="flex flex-col">
              {isSmallScreen ? (
                <div className="flex flex-col flex-grow pb-4">
                  <div className="text-center font-alata font-semibold text-4xl pt-4 pb-6">
                    {note.short_title ? (
                      <h1>{note.short_title}</h1>
                    ) : (
                      <h1>{note.title}</h1>
                    )}
                  </div>
                  <div className="flex flex-row justify-between">
                    <div
                      onClick={handleViewProfile(note.username)}
                      className="flex flex-row w-1/3 space-x-2 cursor-pointer justify-center items-center hover:cursor-pointer"
                    >
                      <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                        <FaUserCircle className="w-6 h-6 text-gray-700" />
                      </div>
                      <div className="justify-center font-outfit">
                        {note.username}
                      </div>
                    </div>
                    <div className="flex flex-row items-center justify-center w-2/3 space-x-10">
                      <div className="flex items-center space-x-2">
                        <VisibilityIcon fontSize="large" />
                        <span className="text-black font-bold">
                          {note.views}
                        </span>
                      </div>
                      <div className="flex items-center justify-end space-x-2">
                        {likeLoading ? (
                          <div className="loader"></div>
                        ) : (
                          <>
                            {note.liked ? (
                              <ThumbUpAltIcon
                                onClick={() => updateLike(false)}
                                fontSize="large"
                                sx={{
                                  color: "blue",
                                  cursor: "pointer",
                                  "&:hover": {
                                    cursor: "pointer",
                                  },
                                }}
                              />
                            ) : (
                              <ThumbUpOffAltIcon
                                onClick={() => updateLike(true)}
                                fontSize="large"
                                sx={{
                                  color: "gray",
                                  cursor: "pointer",
                                  "&:hover": {
                                    cursor: "pointer",
                                  },
                                }}
                              />
                            )}
                            <span className="text-black font-bold">
                              {note.likes}
                            </span>
                          </>
                        )}
                      </div>
                      {favLoading ? (
                        <div className="loader"></div>
                      ) : (
                        <>
                          {note.favorite ? (
                            <BookmarkRemoveTwoToneIcon
                              onClick={() => updateFavorite(false)}
                              fontSize="large"
                              sx={{
                                color: "gold",
                                cursor: "pointer",
                                "&:hover": {
                                  cursor: "pointer",
                                },
                              }}
                            />
                          ) : (
                            <BookmarkAddTwoToneIcon
                              onClick={() => updateFavorite(true)}
                              fontSize="large"
                              sx={{
                                color: "gray",
                                cursor: "pointer",
                                "&:hover": {
                                  cursor: "pointer",
                                },
                              }}
                            />
                          )}
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-grow md:ml-20 md:mr-16 flex-row justify-between">
                  <div
                    className="flex flex-row w-1/5 space-x-4 cursor-pointer justify-center items-center"
                    onClick={handleViewProfile}
                  >
                    <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                      <FaUserCircle className="w-6 h-6 text-gray-700" />
                    </div>
                    <div className="justify-center text-lg font-outfit">
                      {note.username}
                    </div>
                  </div>
                  <div className="text-center font-alata font-semibold text-4xl pt-4 pb-8">
                    {note.short_title ? (
                      <h1 className="">{note.short_title}</h1>
                    ) : (
                      <h1 className="">{note.title}</h1>
                    )}
                  </div>
                  <div className="flex flex-row items-center w-1/5 space-x-10">
                    <div className="flex items-center space-x-2">
                      <VisibilityIcon fontSize="large" />
                      <span className="text-black font-bold">{note.views}</span>
                    </div>
                    <div className="flex items-center justify-end space-x-2">
                      {likeLoading ? (
                        <div className="loader"></div>
                      ) : (
                        <>
                          {note.liked ? (
                            <ThumbUpAltIcon
                              onClick={() => updateLike(false)}
                              fontSize="large"
                              sx={{
                                color: "blue",
                                cursor: "pointer",
                                "&:hover": {
                                  cursor: "pointer",
                                },
                              }}
                            />
                          ) : (
                            <ThumbUpOffAltIcon
                              onClick={() => updateLike(true)}
                              fontSize="large"
                              sx={{
                                color: "gray",
                                cursor: "pointer",
                                "&:hover": {
                                  cursor: "pointer",
                                },
                              }}
                            />
                          )}
                          <span className="text-black font-bold">
                            {note.likes}
                          </span>
                        </>
                      )}
                    </div>
                    {favLoading ? (
                      <div className="loader"></div>
                    ) : (
                      <>
                        {note.favorite ? (
                          <BookmarkRemoveTwoToneIcon
                            onClick={() => updateFavorite(false)}
                            fontSize="large"
                            sx={{
                              color: "gold",
                              cursor: "pointer",
                              "&:hover": {
                                cursor: "pointer",
                              },
                            }}
                          />
                        ) : (
                          <BookmarkAddTwoToneIcon
                            onClick={() => updateFavorite(true)}
                            fontSize="large"
                            sx={{
                              color: "gray",
                              cursor: "pointer",
                              "&:hover": {
                                cursor: "pointer",
                              },
                            }}
                          />
                        )}
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* PDF Viewer */}
              <div className="bg-gray-200 flex flex-grow h-screen md:ml-16 md:mr-10">
                <iframe
                  src={note.s3_path}
                  width="100%"
                  height="100%"
                  style={{ border: "none" }}
                  title="PDF Viewer"
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ViewNote;
