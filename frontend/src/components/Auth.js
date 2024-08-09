import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const Auth = () => {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleToggle = () => {
    setIsSignUp(!isSignUp);
    setError(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const url = isSignUp ? "/api/signup/" : "/api/login/";
    const payload = isSignUp ? { email, name, password } : { email, password };

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (response.ok) {
        // Handle successful response
        console.log("Success:", JSON.stringify(data.user));
        // Clear the form
        setEmail("");
        setName("");
        setPassword("");
        setError(null);
        if (isSignUp) {
          window.alert(
            "Successfully signed up, please check your email to verify your account"
          );
        } else {
          localStorage.setItem("user", JSON.stringify(data.user));
          navigate("/dashboard");
        }
      } else {
        // Handle errors
        setError(data.error);
        if (isSignUp) {
          window.alert("Email is already in use or name is taken");
        } else {
          window.alert("Wrong login information");
        }
        window.location.reload();
      }
    } catch (error) {
      setError("Something went wrong. Please try again.");
    }
  };

  return (
    <>
      <img
        src="../../static/images/NoteSlideLogo.png"
        className="w-12 mx-auto pt-8"
      />
      <div className="wrapper h-screen overflow-hidden">
        <div className="card-switch">
          <label className="switch">
            <input type="checkbox" className="toggle" onChange={handleToggle} />
            <span className="slider"></span>
            <span className="card-side"></span>
            <div className="flip-card__inner">
              <div className={`flip-card__front ${isSignUp ? "flip" : ""}`}>
                <div className="title font-josefin">Log in</div>
                <form className="flip-card__form" onSubmit={handleSubmit}>
                  <input
                    className="flip-card__input"
                    name="email"
                    placeholder="Email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  <input
                    className="flip-card__input"
                    name="password"
                    placeholder="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <button className="flip-card__btn" type="submit">
                    Let's go!
                  </button>
                </form>
              </div>
              <div className={`flip-card__back ${!isSignUp ? "flip" : ""}`}>
                <div className="title font-josefin">Sign up</div>
                <form className="flip-card__form" onSubmit={handleSubmit}>
                  <input
                    className="flip-card__input"
                    name="name"
                    placeholder="Name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                  <input
                    className="flip-card__input"
                    name="email"
                    placeholder="Email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  <input
                    className="flip-card__input"
                    name="password"
                    placeholder="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <button className="flip-card__btn" type="submit">
                    Confirm!
                  </button>
                </form>
              </div>
            </div>
          </label>
          {error && <div className="error-message">{error}</div>}
        </div>
      </div>
    </>
  );
};

export default Auth;
