import "../../static/css/index.css";
import React from "react";
import { useNavigate } from "react-router-dom";

const Hero = () => {
  const navigate = useNavigate();

  const handleNavigation = (path) => {
    navigate(path);
  };

  return (
    <div className="flex flex-col pb-20 md:pb-0 md:min-h-screen bg-white">
      {/* Navigation Bar */}
      <nav className="w-full flex items-center justify-between p-4 px-20 pt-12 animate-floatDown">
        <div className="flex flex-row justify-center w-full md:w-fit items-center space-x-4">
          <img src="../../static/images/NoteSlideLogo.png" className="w-10" />
          <div className="text-2xl text-black font-semibold font-nats">
            Note Slide
          </div>
        </div>
        <div className="hidden md:flex flex-row items-center space-x-12 text-2xl font-josefin">
          <button className="text_button font-reem-kufi bg-white text-gray-700">
            <span className="span-mother">
              <span>I</span>
              <span>n</span>
              <span>f</span>
              <span>o</span>
            </span>
            <span className="span-mother2">
              <span>I</span>
              <span>n</span>
              <span>f</span>
              <span>o</span>
            </span>
          </button>
          <button className="text_button font-reem-kufi bg-white text-gray-700">
            <span className="span-mother">
              <span>R</span>
              <span>e</span>
              <span>v</span>
              <span>i</span>
              <span>e</span>
              <span>w</span>
              <span>s</span>
            </span>
            <span className="span-mother2">
              <span>R</span>
              <span>e</span>
              <span>v</span>
              <span>i</span>
              <span>e</span>
              <span>w</span>
              <span>s</span>
            </span>
          </button>
          <button className="text_button font-reem-kufi bg-white text-green-500">
            <span className="span-mother">
              <span>$</span>
              <span>$</span>
              <span>$</span>
            </span>
            <span className="span-mother2">
              <span>$</span>
              <span>$</span>
              <span>$</span>
            </span>
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <div className="text-center mt-12">
        <div className="mx-4 md:mx-0 text-5xl md:text-7xl flex flex-col text-center font-outfit font-semibold mb-8 animate-floatUp">
          <h1 className="leading-snug">
            Simply the Best Way to <br className="hidden md:block" /> Share
            Notes
          </h1>
        </div>
        <div className="flex flex-row justify-center space-x-16 mt-16 font-josefin">
          <div
            onClick={() => handleNavigation("/auth")}
            className="main w-28 px-8 text-xl animate-floatUp"
          >
            <a href="#">Login</a>
          </div>
          <div
            className="wipe mt-2 py-3 px-6 text-xl animate-floatUp"
            style={{ cursor: "pointer" }}
            onClick={() => (window.location.href = "#whynoteslide")}
          >
            <a href="#whynoteslide" className="">
              Learn
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;
