import Express from "express";
import authRoutes from "./routes/auth.js";
import usersRoutes from "./routes/users.js";
import postsRoutes from "./routes/posts.js";
import likesRoutes from "./routes/likes.js";
import commentsRoutes from "./routes/comments.js";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = Express();

// middlewares
app.use(Express.json());
app.use(cors());
app.use(cookieParser());

app.use("/api/users", usersRoutes);
app.use("/api/posts", postsRoutes);
app.use("/api/comments", commentsRoutes);
app.use("/api/likes", likesRoutes);
app.use("/api/auth", authRoutes);

app.listen(8800, () =>{
    console.log("API working!");
})

