import './Home.css'
import globalState from './persistent.Jsx'

function Home() {
    if (globalState.username === 'blank' && globalState.password === 'blank' && globalState.uid === 999999999999999) {
        window.location.href = '/';
    }
    if (globalState.username === ' ' && globalState.password === ' ' && globalState.uid === 0) {
        window.location.href = '/';
    }
    if (globalState.username === '' && globalState.password === '' && globalState.uid === 0) {
        window.location.href = '/';
    }
    return (
        <div>
            <h1 className="title">Veber</h1>
            <h4 className="subtitle">Welcome, {globalState.username}.</h4>
            <div className="container">
                <h4 className="container-title">
                    What's my balance ?
                </h4>
                <button className="container-action-button">Retrieve</button>
            </div>
            <div className="container">
                <h4 className="container-title">
                    What's my balance ?
                </h4>
                <button className="container-action-button">Retrieve</button>
            </div>
        </div>
    );
}

export default Home;