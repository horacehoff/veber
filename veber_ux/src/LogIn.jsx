import './LogIn.css'
import globalState from './persistent.Jsx'
import {useNavigate} from 'react-router-dom';

function LogIn() {
  const navigate = useNavigate();
  return (
    <div className="App">
    <h1 className="title">Veber</h1>
    <h4 className="subtitle">Welcome back.</h4><br/><br/><br/><br/><br/><br/>
    <input placeholder="Username" id="username" name="username"/><br/>
    <input placeholder='Password' type="password" id="password" name="password"/><br/>
    <input placeholder='UID' type="number" id="uid" name="uid"/><br/>
    <button className="action-button" onClick={() => {
      if (document.getElementById('username').value === '' || document.getElementById('password').value === '' || document.getElementById('uid').value === '') {
        alert('Please fill out all fields.');
      } else {
        globalState.username = document.getElementById('username').value;
        globalState.password = document.getElementById('password').value;
        globalState.uid = document.getElementById('uid').value;
        navigate('/home');
    }
    }}>Log-In / Sign-Up</button>
    </div>
  )
}

export default LogIn
