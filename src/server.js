const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/v1/health", (req, res) => {
    res.json({
        success: true,
        service: "Shield API",
        version: "1.0.0"
    });
});

app.listen(PORT, () => {
    console.log(`Shield API listening on port ${PORT}`);
});