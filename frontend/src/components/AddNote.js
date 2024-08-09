import React, { useState, useEffect } from "react";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import HomeIcon from "@mui/icons-material/Home";
import StarIcon from "@mui/icons-material/Star";
import StorefrontIcon from "@mui/icons-material/Storefront";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BusinessCenterIcon from "@mui/icons-material/BusinessCenter";
import { FaBars, FaSearch, FaBell, FaUserCircle } from "react-icons/fa";
import { useNavigate } from "react-router-dom";

const AddNote = () => {
  const MAX_FILE_SIZE_MB = 1024; // 1 GB in MB
  const [selectedFile, setSelectedFile] = useState(null);
  const [title, setTitle] = useState("");
  const [shortTitle, setShortTitle] = useState("");
  const [description, setDescription] = useState("");
  const [interest, setInterest] = useState("");
  const [loading, setLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useNavigate();
  const user = JSON.parse(localStorage.getItem("user"));

  useEffect(() => {
    if (!user) {
      navigate("/auth");
    }
  }, [user, navigate]);

  const interests = [
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
    setTitle(event.target.value.slice(0, 50));
  };

  const handleShortTitleChange = (event) => {
    setShortTitle(event.target.value.slice(0, 20)); // Limit to 20 characters
  };

  const handleInterestChange = (event) => {
    setInterest(event.target.value);
  };

  const handleDescriptionChange = (event) => {
    setDescription(event.target.value.slice(0, 300));
  };

  const handleUpload = async () => {
    setLoading(true);
    if (!selectedFile || !title || !shortTitle || !interest || !description) {
      alert("Please fill all fields and select a file.");
      return;
    }

    try {
      const formData = new FormData();
      formData.append("pdf_file", selectedFile);
      formData.append("title", title);
      formData.append("short_title", shortTitle);
      formData.append("description", description);
      formData.append("user", user.name);
      formData.append("user_id", user.id);
      formData.append("interest", interest);

      const uploadUrl = "/api/uploadnote/";

      const response = await fetch(uploadUrl, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Error uploading file.");
      }

      const data = await response.json();
      console.log("File uploaded successfully:", data);
      alert("File uploaded successfully!");
      setSelectedFile(null); // Clear selected file after upload
      setTitle(""); // Clear title after upload
      setShortTitle(""); // Clear short title after upload
      setInterest(""); // Clear interest after upload
    } catch (error) {
      console.error("Error uploading file:", error);
      alert("Error uploading file. Please try again.");
    }
    setLoading(false);
  };

  const handleClear = () => {
    setSelectedFile(null);
    setTitle("");
    setShortTitle("");
    setInterest("");
  };

  const handleNavigation = (path) => {
    navigate(path);
  };

  return (
    <div className="flex h-screen overflow-auto ml-6">
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

        {/* Upload */}
        <div className="w-full md:w-3/5 mx-auto p-6 pt-3 bg-white rounded-lg">
          <div className="flex flex-col items-center pb-4 pt-4">
            <input
              type="text"
              value={title}
              onChange={handleTitleChange}
              placeholder="Enter title"
              className="mb-4 px-4 py-2 border border-gray-600 rounded-md w-full md:w-3/5 justify-center"
              maxLength="50"
            />
            <input
              type="text"
              value={shortTitle}
              onChange={handleShortTitleChange}
              placeholder="Enter short title (max 30 characters)"
              className="mb-4 px-4 py-2 border border-gray-600 rounded-md w-full md:w-3/5 justify-center"
              maxLength="30"
            />
            <select
              value={interest}
              onChange={handleInterestChange}
              className="mb-4 px-4 py-2 border border-gray-600 rounded-md w-full md:w-3/5 justify-center"
            >
              <option value="">Select interest</option>
              {interests.map((interest, index) => (
                <option key={index} value={interest}>
                  {interest}
                </option>
              ))}
            </select>
            <div className="w-full md:w-4/5 mx-auto flex flex-row space-x-8">
              <div className="w-1/2 text-center">
                <label
                  htmlFor="file-upload"
                  className="p-6 mb-2 flex flex-col items-center justify-center h-auto bg-zinc-100 rounded-2xl border-2 border-dashed border-gray-400 cursor-pointer"
                >
                  <CloudUploadIcon style={{ fontSize: 40, color: "gray" }} />
                  <span className="mt-2 text-base leading-normal text-center text-gray-600">
                    Drag & drop your PDF here, or click to select
                  </span>
                  <input
                    id="file-upload"
                    type="file"
                    className="hidden"
                    onChange={handleFileChange}
                  />
                </label>
                {selectedFile && (
                  <p className="font-semibold text-sm text-gray-600">
                    Selected file: {selectedFile.name}
                  </p>
                )}
                {!selectedFile && (
                  <a
                    href="https://smallpdf.com/jpg-to-pdf"
                    target="_blank"
                    className="text-md text-gray-600 underline hover:text-black"
                  >
                    Covert image to pdf
                  </a>
                )}
              </div>
              <div className="w-1/2">
                <textarea
                  type="text"
                  value={description}
                  onChange={handleDescriptionChange}
                  placeholder="Enter description (300 characters max)"
                  className="mb-4 flex flex-grow w-full h-40 px-4 py-2 border border-gray-600 rounded-md text-start justify-center"
                  maxLength="300"
                />
              </div>
            </div>

            <div className="mt-6 flex flex-row items-center">
              {loading ? (
                <div className="loader"></div>
              ) : (
                <div
                  onClick={handleUpload}
                  disabled={
                    !selectedFile ||
                    !title ||
                    !shortTitle ||
                    !interest ||
                    !description
                  }
                  className="main w-28 px-8 py-4 text-xl"
                >
                  <a href="#">Upload</a>
                </div>
              )}

              {selectedFile && (
                <div className="ml-12">
                  <button
                    className="pt-3 pb-2 font-josefin px-6 text-lg text-gray-600 border-2 border-gray-600 bg-white hover:text-white hover:bg-gray-600 transition duration-200"
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

export default AddNote;
