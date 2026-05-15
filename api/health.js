module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.status(200).json({ status: "ok", service: "Zerolyze API", version: "1.0.0" });
};
