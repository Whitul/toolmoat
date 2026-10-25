---
name: frontend-design
description: Create distinctive, production-grade frontend interfaces with high design quality. Use when the user asks to build web components, pages or applications, or to improve the look of an existing UI.
license: MIT
---

# Frontend design

This skill guides the creation of distinctive, production-grade frontend
interfaces that avoid generic "AI slop" aesthetics. Implement real working code
with careful attention to aesthetic details and creative choices.

The user provides frontend requirements: a component, page, application or
interface to build. They may include context about the purpose, audience or
technical constraints.

## Design thinking

Before coding, understand the context and commit to a bold aesthetic direction:

- **Purpose**: What problem does this interface solve? Who uses it?
- **Tone**: Pick an extreme: brutally minimal, maximalist chaos, retro-futuristic,
  organic and natural, luxury and refined, playful and toy-like, editorial and
  magazine, brutalist and raw, art deco and geometric, soft and pastel,
  industrial and utilitarian. Use these for inspiration but design one that is
  true to the aesthetic direction.
- **Constraints**: Technical requirements such as the framework, performance
  budget and accessibility level.
- **Differentiation**: What makes this unforgettable? What is the one thing
  someone will remember?

Choose a clear conceptual direction and execute it with precision. Bold
maximalism and refined minimalism both work; the key is intentionality, not
intensity.

Then implement working code (HTML/CSS/JS, React, Vue, Svelte) that is:

- Production-grade and functional
- Visually striking and memorable
- Cohesive, with a clear aesthetic point of view
- Meticulously refined in every detail

## Aesthetics guidelines

### Typography

Choose fonts that are beautiful, unique and interesting. Avoid generic fonts
such as Arial and Inter; opt for distinctive choices that elevate the
frontend's aesthetics. Pair a distinctive display font with a refined body
font.

### Color and theme

Commit to a cohesive palette. Use CSS variables for consistency. Dominant
colors with sharp accents outperform timid, evenly distributed palettes.

```css
:root {
  --ink: #1b1a17;
  --paper: #f4efe6;
  --accent: #d6452f;
  --muted: #8a8174;
}

@media (prefers-color-scheme: dark) {
  :root {
    --ink: #f4efe6;
    --paper: #15140f;
  }
}
```

### Motion

Use animations for effects and micro-interactions. Prefer CSS-only solutions
for HTML, and the Motion library for React when it is available. Focus on
high-impact moments: one well-orchestrated page load with staggered reveals
(`animation-delay`) creates more delight than scattered micro-interactions.
Use scroll-triggering and hover states that surprise.

```css
.card {
  opacity: 0;
  transform: translateY(12px);
  animation: rise 600ms cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
}

.card:nth-child(2) { animation-delay: 80ms; }
.card:nth-child(3) { animation-delay: 160ms; }

@keyframes rise {
  to { opacity: 1; transform: none; }
}
```

### Spatial composition

Unexpected layouts. Asymmetry. Overlap. Diagonal flow. Grid-breaking
elements. Generous negative space or controlled density.

### Backgrounds and visual details

Create atmosphere and depth rather than defaulting to solid colors. Add
contextual effects and textures that match the overall aesthetic: gradient
meshes, noise textures, geometric patterns, layered transparencies, dramatic
shadows, decorative borders and grain overlays.

## Accessibility

- Keep text contrast at WCAG AA or better.
- Every interactive element must be reachable and usable with the keyboard,
  with a visible focus style.
- Respect `prefers-reduced-motion`:

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

- Use semantic elements (`<nav>`, `<main>`, `<button>`) before ARIA.
- Hide decorative images from screen readers with `alt=""` and give every
  meaningful image a real description.

## Implementation checklist

1. Sketch the layout and pick the type scale before writing components.
2. Build the static markup with semantic elements.
3. Add the design tokens as CSS variables.
4. Style mobile first, then add breakpoints.
5. Add motion last, behind `prefers-reduced-motion`.
6. Test at 320px, 768px and 1440px wide, in light and dark mode.

Never converge on common choices across generations. Vary between light and
dark themes, different fonts and different aesthetics. Match implementation
complexity to the aesthetic vision: maximalist designs need elaborate code
with extensive animations and effects; minimalist designs need restraint,
precision and careful attention to spacing and typography.
