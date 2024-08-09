import React from "react";

const Testimonials = () => {
  return (
    <div
      className="flex flex-col items-center space-y-8 pt-20 min-h-screen pb-12 p-6 bg-white"
      id="testimonials"
    >
      <div className="flex flex-col space-y-6 md:space-y-0 md:flex-row md:space-x-16 mx-auto mb-4 w-4/5">
        <div className="relative border-2 border-black p-4 py-6 rounded shadow-md w-4/5 mx-auto text-center">
          <div className="triangle -left-0.5 -top-0.5"></div>
          <div className="text-3xl pb-2 text-black font-bold mb-2">★★★★★</div>
          <p className="text-neutral-800 text-2xl font-outfit mx-4">
            “I used to hate sending all my friends notes one by one”
          </p>
        </div>
        <div className="relative border-2 border-black p-4 py-6 rounded shadow-md w-4/5 mx-auto text-center">
          <div className="triangle -left-0.5 -top-0.5"></div>
          <div className="text-3xl pb-2 font-bold mb-2">★★★★★</div>
          <p className="text-neutral-800 text-2xl font-outfit mx-4">
            “I don’t have to scour online like a vulture anymore!”
          </p>
        </div>
        <div className="relative border-2 border-black p-4 py-6 rounded shadow-md w-4/5 mx-auto text-center">
          <div className="triangle -left-0.5 -top-0.5"></div>
          <div className="text-3xl pb-2 font-bold mb-2">★★★★★</div>
          <p className="text-neutral-800 text-2xl font-outfit mx-4">
            “Can’t wait to see how much I can make when this platform grows”
          </p>
        </div>
      </div>
      <div className="flex flex-row pt-10 items-center">
        <div className="flex text-center text-3xl font-outfit font-semibold">
          “This needs to be used by every single student”
        </div>
        <div
          className="wipe ml-8 py-2 px-6 text-xl text-center"
          style={{ cursor: "pointer" }}
          onClick={() => (window.location.href = "#")}
        >
          <a href="#" className="font-outfit font-medium">
            Join Us
          </a>
        </div>
      </div>
      <div className="text-center text-5xl text-neutral-600 pt-12 font-outfit">
        It’s Free, Why Not Try it Out?
      </div>
    </div>
  );
};

export default Testimonials;
