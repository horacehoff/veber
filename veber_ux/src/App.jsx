import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import LogIn from './LogIn';
import Home from './Home';
function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<LogIn />}/>
                <Route path="/home" element={<Home />}/>
            </Routes>
        </Router>
    )
}

export default App;