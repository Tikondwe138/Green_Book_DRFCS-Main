document.getElementById("national_id").addEventListener("change", function() {
    let nationalId = this.value;

    fetch("/verify", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ national_id: nationalId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "verified") {
            document.getElementById("name").value = data.name;
            document.getElementById("dob").value = data.dob;
            document.getElementById("gender").value = data.gender;
            document.getElementById("address").value = data.address;
            document.getElementById("status").innerHTML = "<span style='color:green'>Verified</span>";
        } else {
            document.getElementById("status").innerHTML = "<span style='color:red'>National ID Not Found</span>";
        }
    });
});
