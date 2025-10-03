let cart = [];
let total = 0;

document.addEventListener("DOMContentLoaded", function () {
  const buttons = document.querySelectorAll(".add-to-cart");

  buttons.forEach(button => {
    button.addEventListener("click", function () {
      let name = this.getAttribute("data-name");
      let price = parseFloat(this.getAttribute("data-price"));

      // Add to cart array
      cart.push({ name, price });
      total += price;

      // Update cart summary
      document.getElementById("cart-count").innerText = cart.length;
      document.getElementById("cart-total").innerText = total.toFixed(2);
    });
  });
});
