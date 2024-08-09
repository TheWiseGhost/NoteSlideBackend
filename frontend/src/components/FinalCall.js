import React from "react";
import "../../static/css/index.css";

const FinalCall = () => {
  return (
    <div className="min-h-screen bg-white flex flex-col px-20 pt-20 pb-12">
      <div className="text-center">
        <h1 className="text-6xl font-outfit font-semibold text-center">
          You've read our Notes
        </h1>
      </div>
      <div className="pt-12 text-center">
        <p className="text-neutral-600 text-3xl font-outfit">
          You know everything we can <br className="hidden md:block" /> do for
          you
        </p>
      </div>
      <div className="flex flex-row pt-20 mx-auto space-x-12 justify-center items-center">
        <div className="flex w-full justify-end">
          <div className="flex main w-40 py-6 text-2xl">
            <a href="#">Sign Up</a>
          </div>
        </div>
        <div className="w-3 h-32 bg-gray-300"></div>
        <div className="w-full justify-center">
          <p className="w-full md:w-3/5 text-sm md:text-2xl mr-auto font-josefin text-black">
            Nah, I prefer doing all the work by myself
          </p>
        </div>
      </div>
    </div>
  );
};

export default FinalCall;
