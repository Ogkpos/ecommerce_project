import React from "react";
import Landingpage from "./components/Landingpage";
import { Route, Routes } from "react-router-dom";
import PageNotFound from "./components/PageNotFound";
import "./App.css";
import Login from "./components/Login";


function App() {
  return (
    <Routes>
      <Route path="/" element={<Landingpage />} />
      <Route path="/login" element={<Login />} />
      {/*--path="*" helps display an error && navigate to "pageNotFound" if user navigates to a page that doesnt exist*/}
      <Route path="*" element={<PageNotFound />} />
    </Routes>
  );
}

export default App;
