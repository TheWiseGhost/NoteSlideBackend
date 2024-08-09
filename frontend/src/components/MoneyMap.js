import React from "react";

const MoneyMap = () => {
  return (
    <div
      className="relative flex flex-col min-h-screen mt-20 mb-20 items-center"
      id="moneymap"
    >
      <div>
        <h1 className="text-center font-outfit font-semibold text-5xl">
          Money Map
        </h1>
      </div>
      <div className="relative flex flex-col w-full min-h-screen mt-20 mb-12 items-center">
        {/* Central Line */}
        <div className="absolute w-1 hidden md:block h-full bg-gray-400"></div>

        <div className="container mx-auto flex flex-col items-center space-y-8 md:space-y-0">
          {/* Staggered Divs */}
          <div className="relative flex flex-row justify-start items-center w-3/5 mr-auto ml-36">
            <div className="border-2 border-black w-full md:w-1/2 text-2xl font-alata p-8 rounded-md shadow-md">
              <div className="triangle -left-0.5 -top-0.5"></div>
              <p>
                You probably have a TON of notes buried in your Google Drive or
                online
              </p>
            </div>
          </div>
          <div className="relative flex flex-row justify-end items-center w-3/5 ml-auto mr-36">
            <div className="border-2 border-black w-full md:w-1/2 text-2xl font-alata p-8 rounded-md shadow-md">
              <div className="triangle rotate-90 -right-0.5 -top-0.5"></div>
              <p>Why not upload them to Note Slide and make some $$$</p>
            </div>
          </div>
          <div className="relative flex flex-row justify-start items-center w-3/5 mr-auto ml-36">
            <div className="border-2 border-black w-full md:w-1/2 text-2xl font-alata p-8 rounded-md shadow-md">
              <div className="triangle -left-0.5 -top-0.5"></div>
              <p>Creators earn an average of one dollar per 100 views.</p>
            </div>
          </div>
          <div className="relative flex flex-row justify-end items-center w-3/5 ml-auto mr-36">
            <div className="border-2 border-black w-full md:w-1/2 text-2xl font-alata p-8 rounded-md shadow-md">
              <div className="triangle rotate-90 -right-0.5 -top-0.5"></div>
              <p>
                With millions of students in the US alone, there’s plenty of
                people looking for your notes
              </p>
            </div>
          </div>
        </div>
      </div>
      <div>
        <h1 className="text-center text-green-500 font-outfit font-semibold text-5xl">
          $$$
        </h1>
      </div>
    </div>
  );
};

export default MoneyMap;
