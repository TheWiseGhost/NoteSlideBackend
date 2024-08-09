import React, { useEffect, useRef } from "react";
import LocomotiveScroll from "locomotive-scroll";
import "locomotive-scroll/dist/locomotive-scroll.css";
import Hero from "./Hero";
import WhyNoteSlide from "./WhyNoteSlide";
import "../../static/css/index.css";
import Reviews from "./Reviews";
import MoneyMap from "./MoneyMap";
import Testimonials from "./Testimonials";
import FinalCall from "./FinalCall";

const LandingPage = () => {
  const scrollRef = useRef(null);
  const scrollInstanceRef = useRef(null);

  useEffect(() => {
    scrollInstanceRef.current = new LocomotiveScroll({
      el: scrollRef.current,
      smooth: true,
    });

    return () => {
      if (scrollInstanceRef.current) scrollInstanceRef.current.destroy();
    };
  }, []);

  return (
    <div id="scroll-container" data-scroll-container ref={scrollRef}>
      <div data-scroll-section>
        <Hero />
        <WhyNoteSlide />
        <Reviews />
        <MoneyMap />
        <Testimonials />
        <FinalCall />
      </div>
    </div>
  );
};

export default LandingPage;
