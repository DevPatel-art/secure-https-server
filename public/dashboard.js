async function fetchProfile() {
  const errorBox = document.getElementById("errorBox");

  try {
    const res = await fetch("/api/profile", {
      credentials: "include",
    });

    if (!res.ok) {
      throw new Error("Failed to load profile");
    }

    const data = await res.json();

    document.getElementById("userName").textContent = data.name || "";
    document.getElementById("userEmail").textContent = data.email || "";

    document.getElementById("name").value = data.name || "";
    document.getElementById("email").value = data.email || "";
    document.getElementById("bio").value = data.bio || "";
  } catch (err) {
    console.error(err);
    errorBox.textContent = "Could not load profile. Please try again.";
  }
}

async function updateProfile(event) {
  event.preventDefault();

  const errorBox = document.getElementById("errorBox");
  const successBox = document.getElementById("successBox");
  errorBox.textContent = "";
  successBox.textContent = "";

  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const bio = document.getElementById("bio").value.trim();

  try {
    const res = await fetch("/api/profile", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ name, email, bio }),
    });

    const data = await res.json();

    if (!res.ok) {
      console.error(data);
      errorBox.textContent =
        data.message || "Failed to update profile. Check your inputs.";
      return;
    }

    successBox.textContent = "Profile updated successfully!";

    document.getElementById("userName").textContent = data.user.name || "";
    document.getElementById("userEmail").textContent = data.user.email || "";
  } catch (err) {
    console.error(err);
    errorBox.textContent = "An error occurred. Please try again.";
  }
}

async function logout() {
  try {
    const res = await fetch("/auth/logout", {
      method: "GET",
      credentials: "include",
    });
    if (res.ok) {
      window.location.href = "/";
    }
  } catch (err) {
    console.error(err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  fetchProfile();

  document
    .getElementById("profileForm")
    .addEventListener("submit", updateProfile);

  document.getElementById("logoutBtn").addEventListener("click", logout);
});
