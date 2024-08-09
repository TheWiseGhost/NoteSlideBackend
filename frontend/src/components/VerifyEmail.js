import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useNavigate } from "react-router-dom";

const VerifyEmail = () => {
  const { token } = useParams();
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const verifyEmail = async () => {
      try {
        const response = await fetch(`/api/verify/${token}/`, {
          method: "GET",
        });
        const data = await response.json();
        if (response.ok) {
          setMessage(data.message);
          window.alert(message);
          navigate("/auth");
        } else {
          setMessage(data.error);
          window.alert(message);
        }
      } catch (error) {
        setMessage("An error occurred while verifying your email.");
      }
    };

    verifyEmail();
  }, [token]);

  return <div className="items-center justify-center"></div>;
};

export default VerifyEmail;
