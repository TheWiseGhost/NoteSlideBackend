const path = require("path");
const webpack = require("webpack");

module.exports = {
  entry: "./src/index.js",
  output: {
    path: path.resolve(__dirname, "static/frontend"),
    filename: "main.js",
    publicPath: "/static/frontend/",
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
        },
      },
      {
        test: /\.css$/,
        use: ["style-loader", "css-loader", "postcss-loader"],
      },
    ],
  },
  resolve: {
    extensions: [".js", ".jsx"],
  },
  plugins: [
    new webpack.DefinePlugin({
      "process.env.NODE_ENV": JSON.stringify("development"),
    }),
  ],
  optimization: {
    minimize: false,
  },
  devServer: {
    static: {
      directory: path.resolve(__dirname, "static/frontend"),
    },
    compress: true,
    port: 3000,
    hot: true,
    historyApiFallback: true,
  },
};
