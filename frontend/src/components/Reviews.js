import React, { useState, useEffect } from "react";
import { ReactTyped } from "react-typed";
import "../../static/css/index.css";

const Reviews = () => {
  return (
    <div className="flex flex-col items-center pt-16 min-h-screen bg-white p-4">
      <h1 className="text-center text-4xl mb-12 font-outfit font-semibold">
        Join the best platform to gain info for{" "}
        <span>
          <ReactTyped
            strings={[
              "Students",
              "Writers",
              "Developers",
              "Scholars",
              "Researchers",
            ]}
            typeSpeed={100}
            loop
            backSpeed={80}
            cursorChar="|"
            showCursor={true}
            backDelay={2000}
          />
        </span>
      </h1>
      <div className="flex flex-col space-y-8 md:space-y-0 md:flex-row md:space-x-20 mb-4 w-3/5 mx-auto">
        <div className="relative border-2 border-black p-4 py-6 rounded shadow-md w-full md:w-4/5 mx-auto text-center">
          <div className="triangle -left-0.5 -top-0.5"></div>
          <div className="text-3xl pb-2 text-black font-bold mb-2">★★★★★</div>
          <p className="text-neutral-800 text-2xl font-outfit mx-4">
            “Made my first $100 in just my second week”
          </p>
        </div>
        <div className="relative border-2 border-black p-4 py-6 rounded shadow-md w-full md:w-4/5 mx-auto text-center">
          <div className="triangle rotate-90 -right-0.5 -top-0.5"></div>
          <div className="text-3xl pb-2 font-bold mb-2">★★★★★</div>
          <p className="text-neutral-800 text-2xl font-outfit mx-4">
            “Learned so much in just minutes!”
          </p>
        </div>
      </div>
      <div className="flex flex-row items-center justify-center space-x-16 mb-4 mt-8">
        <div className="flex items-center w-1/5">
          <img
            src="../static/images/GoogleReviews.png"
            alt="Google"
            className="w-full pt-6 mr-2"
          />
        </div>
        <div
          className="flex wipe items-center py-4 px-6 text-xl mt-6"
          style={{ cursor: "pointer" }}
          onClick={() => (window.location.href = "#")}
        >
          <a href="#" className="font-outfit">
            Get Notes
          </a>
        </div>
        <div className="flex items-center w-1/5">
          <img
            src="../static/images/Trustpilot.png"
            alt="Trustpilot"
            className="w-full pt-6 mr-2"
          />
        </div>
      </div>
    </div>
  );
};

export default Reviews;
